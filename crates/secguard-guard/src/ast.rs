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
}

impl EffectiveCommand {
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
}

/// Parse a raw bash command. Always returns a list of commands (possibly
/// empty) and a flag indicating whether the parse hit any error nodes.
pub fn parse(source: &str) -> ParseResult {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return ParseResult {
            commands: Vec::new(),
            had_error: true,
        };
    }
    let Some(tree) = parser.parse(source, None) else {
        return ParseResult {
            commands: Vec::new(),
            had_error: true,
        };
    };

    let bytes = source.as_bytes();
    let mut walker = Walker::new(bytes);
    walker.walk_program(tree.root_node());

    ParseResult {
        commands: walker.commands,
        had_error: tree_has_error(&tree),
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
}

impl<'a> Walker<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            commands: Vec::new(),
            cwd: None,
        }
    }

    fn text(&self, node: Node<'_>) -> &'a str {
        node.utf8_text(self.src).unwrap_or("")
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
            "pipeline" => {
                self.handle_pipeline(node, wrappers, remote, chrooted);
            }
            "subshell" => {
                // `(...)` runs in a child shell — cd inside does NOT
                // leak out. Save/restore cwd around the subshell body.
                let saved = self.cwd.clone();
                self.walk_named_children(node, wrappers, remote, chrooted);
                self.cwd = saved;
            }
            // Heredocs and comments are pure data — never executable.
            "heredoc_redirect" | "comment" => {}
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
                        for mut cmd in parse(body).commands {
                            let mut chain = wrappers.to_vec();
                            chain.push(Wrapper::Shell);
                            chain.extend(cmd.wrappers.into_iter());
                            cmd.wrappers = chain;
                            if cmd.cwd.is_none() {
                                cmd.cwd = self.cwd.clone();
                            }
                            self.commands.push(cmd);
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
                "command_substitution" | "process_substitution" => {
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
        for child in &children {
            match child.kind() {
                "command_name" | "word" | "concatenation" | "number" => {
                    argv.push(self.text(*child).to_string());
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
                _ => {}
            }
        }

        if argv.is_empty() {
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
                Some(target) if target.starts_with('/') && !target.contains("..") => {
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
        let mut chain: Vec<Wrapper> = wrappers.to_vec();
        let mut acc_remote = remote;
        let mut acc_chrooted = chrooted;
        loop {
            let Some((wrapper, inner, r, c, body)) = unwrap_wrapper(&current_argv) else {
                break;
            };
            chain.push(wrapper);
            acc_remote = acc_remote || r;
            acc_chrooted = acc_chrooted || c;
            if let Some(body) = body {
                // Re-parse the literal `-c BODY` payload as fresh bash.
                let inner_cmds = parse(&body).commands;
                if !inner_cmds.is_empty() {
                    for mut cmd in inner_cmds {
                        let mut full_chain = chain.clone();
                        full_chain.extend(cmd.wrappers.into_iter());
                        cmd.wrappers = full_chain;
                        cmd.remote = cmd.remote || acc_remote;
                        cmd.chrooted = cmd.chrooted || acc_chrooted;
                        if cmd.cwd.is_none() {
                            cmd.cwd = self.cwd.clone();
                        }
                        self.commands.push(cmd);
                    }
                    return;
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
            current_argv = inner;
        }

        self.commands.push(EffectiveCommand {
            argv: current_argv,
            cwd: self.cwd.clone(),
            span: SpanKind::Executed,
            wrappers: chain,
            remote: acc_remote,
            chrooted: acc_chrooted,
        });
    }
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
            // `eval "BODY"` re-parses BODY when it's literal text.
            // When BODY contains a variable expansion or command
            // substitution we cannot see what executes — emit a
            // synthetic `__eval_dynamic__` marker so a rule can fire,
            // rather than silently dropping it. This closes the
            // bypass `X='rm -rf /etc'; eval "$X"`.
            if argv.len() < 2 {
                return None;
            }
            let body = argv[1..].join(" ");
            let dynamic = argv[1..]
                .iter()
                .any(|t| t.starts_with('$') || t.contains("$(") || t.contains('`'));
            if dynamic {
                return Some((
                    Wrapper::Shell,
                    vec!["__eval_dynamic__".to_string(), body],
                    false,
                    false,
                    None,
                ));
            }
            Some((Wrapper::Shell, Vec::new(), false, false, Some(body)))
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
        // `eval "$X"` — dynamic body, content unknown. Walker emits
        // a synthetic `__eval_dynamic__` marker for a rule to fire.
        let c = cmds("eval \"$X\"");
        assert!(c.iter().any(|cmd| cmd.argv[0] == "__eval_dynamic__"));
    }

    #[test]
    fn eval_literal_still_reparsed() {
        // Literal body still re-parsed normally.
        let c = cmds("eval 'rm -rf /etc'");
        assert!(c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]));
    }
}
