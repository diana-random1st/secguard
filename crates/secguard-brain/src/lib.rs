//! secguard-brain: GGUF micro-brain inference for secguard classifiers.
//!
//! Provides [`MicroBrain`] — a reusable ChatML (Qwen) classifier that loads
//! a GGUF model and returns constrained labels via greedy decode.

use std::collections::HashSet;
use std::path::Path;

use llama_cpp_2::context::params::{KvCacheType, LlamaContextParams};
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::token::LlamaToken;
use log::{info, warn};

const NEWLINE: i32 = 198;

/// Configuration for loading a micro-brain.
pub struct BrainConfig<'a> {
    pub system_prompt: &'a str,
    pub valid_labels: &'a [&'a str],
    pub context_size: u32,
    pub max_tokens: usize,
}

impl<'a> BrainConfig<'a> {
    pub fn new(system_prompt: &'a str, valid_labels: &'a [&'a str]) -> Self {
        Self {
            system_prompt,
            valid_labels,
            context_size: 512,
            max_tokens: 10,
        }
    }

    pub fn with_context_size(mut self, size: u32) -> Self {
        self.context_size = size;
        self
    }

    pub fn with_max_tokens(mut self, max: usize) -> Self {
        self.max_tokens = max;
        self
    }
}

/// A loaded GGUF micro-brain classifier.
pub struct MicroBrain {
    model: LlamaModel,
    system_prompt: String,
    valid_labels: HashSet<String>,
    context_size: u32,
    max_tokens: usize,
    im_start: LlamaToken,
    im_end: LlamaToken,
    backend: LlamaBackend,
}

impl MicroBrain {
    pub fn load(model_path: &Path, config: BrainConfig) -> Option<Self> {
        if !model_path.exists() {
            warn!("brain model not found: {}", model_path.display());
            return None;
        }

        if std::env::var("GGML_LOG_LEVEL").is_err() {
            // SAFETY: called before any threads are spawned by llama backend
            unsafe { std::env::set_var("GGML_LOG_LEVEL", "error") };
        }

        let backend = match LlamaBackend::init() {
            Ok(b) => b,
            Err(e) => {
                warn!("brain: failed to init llama backend: {}", e);
                return None;
            }
        };

        let model_params = LlamaModelParams::default().with_n_gpu_layers(99);
        let model = match LlamaModel::load_from_file(&backend, model_path, &model_params) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "brain: failed to load model {}: {}",
                    model_path.display(),
                    e
                );
                return None;
            }
        };

        let valid_labels = config.valid_labels.iter().map(|s| s.to_string()).collect();
        let im_end = model.token_eos();
        let im_start = LlamaToken::new(im_end.0 - 1);
        info!(
            "brain loaded: {} ({} labels, ctx={}, im_start={}, im_end={})",
            model_path.display(),
            config.valid_labels.len(),
            config.context_size,
            im_start.0,
            im_end.0,
        );

        Some(Self {
            backend,
            model,
            system_prompt: config.system_prompt.to_string(),
            valid_labels,
            context_size: config.context_size,
            max_tokens: config.max_tokens,
            im_start,
            im_end,
        })
    }

    /// Load from `~/.secguard/models/{name}.gguf`.
    pub fn load_default(name: &str, config: BrainConfig) -> Option<Self> {
        let path = dirs::home_dir()?
            .join(".secguard")
            .join("models")
            .join(format!("{name}.gguf"));
        Self::load(&path, config)
    }

    pub fn classify(&self, input: &str) -> Option<String> {
        let raw = self.infer(input)?;
        let label = raw.trim().to_lowercase();
        if self.valid_labels.contains(&label) {
            Some(label)
        } else {
            warn!(
                "brain: unexpected output '{}', valid: {:?}",
                label, self.valid_labels
            );
            None
        }
    }

    pub fn classify_raw(&self, input: &str) -> Option<String> {
        self.infer(input).map(|s| s.trim().to_string())
    }

    pub fn classify_with_confidence(&self, input: &str) -> Option<(String, f32)> {
        self.infer_with_confidence_inner(input, &self.system_prompt)
    }

    fn infer_with_confidence_inner(
        &self,
        input: &str,
        system_prompt: &str,
    ) -> Option<(String, f32)> {
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(std::num::NonZeroU32::new(self.context_size))
            .with_type_k(KvCacheType::BF16)
            .with_type_v(KvCacheType::BF16);
        let mut ctx = match self.model.new_context(&self.backend, ctx_params) {
            Ok(c) => c,
            Err(_) => return None,
        };

        let im_start = self.im_start;
        let im_end = self.im_end;
        let nl = LlamaToken::new(NEWLINE);

        let system_label = self.model.str_to_token("system", AddBos::Never).ok()?;
        let system_text = self.model.str_to_token(system_prompt, AddBos::Never).ok()?;
        let user_label = self.model.str_to_token("user", AddBos::Never).ok()?;
        let user_text = self.model.str_to_token(input, AddBos::Never).ok()?;
        let assistant_label = self.model.str_to_token("assistant", AddBos::Never).ok()?;
        let think_suffix = self
            .model
            .str_to_token("<think>\n\n</think>\n\n", AddBos::Never)
            .ok()?;

        let mut tokens = Vec::new();
        tokens.push(im_start);
        tokens.extend_from_slice(&system_label);
        tokens.push(nl);
        tokens.extend_from_slice(&system_text);
        tokens.push(im_end);
        tokens.push(nl);
        tokens.push(im_start);
        tokens.extend_from_slice(&user_label);
        tokens.push(nl);
        tokens.extend_from_slice(&user_text);
        tokens.push(im_end);
        tokens.push(nl);
        tokens.push(im_start);
        tokens.extend_from_slice(&assistant_label);
        tokens.push(nl);
        tokens.extend_from_slice(&think_suffix);

        let mut batch = LlamaBatch::new(tokens.len(), 1);
        for (i, &token) in tokens.iter().enumerate() {
            let is_last = i == tokens.len() - 1;
            if batch.add(token, i as i32, &[0], is_last).is_err() {
                return None;
            }
        }

        if ctx.decode(&mut batch).is_err() {
            return None;
        }

        let candidates = ctx.token_data_array_ith(batch.n_tokens() - 1);
        let max_logit = candidates
            .data
            .iter()
            .map(|d| d.logit())
            .fold(f32::NEG_INFINITY, f32::max);
        let exp_sum: f32 = candidates
            .data
            .iter()
            .map(|d| (d.logit() - max_logit).exp())
            .sum();
        let (top_idx, _) = candidates
            .data
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.logit().partial_cmp(&b.logit()).unwrap())
            .unwrap();
        let top_token = &candidates.data[top_idx];
        let confidence = (top_token.logit() - max_logit).exp() / exp_sum;

        let new_token = top_token.id();
        if self.model.is_eog_token(new_token) {
            return None;
        }

        let mut output = String::new();
        let piece_bytes = self
            .model
            .token_to_piece_bytes(new_token, 32, true, None)
            .ok()?;
        output.push_str(&String::from_utf8_lossy(&piece_bytes));

        let trimmed = output.trim().to_lowercase();
        if self.valid_labels.contains(&trimmed) {
            return Some((trimmed, confidence));
        }

        let mut n_cur = tokens.len();
        batch.clear();
        if batch.add(new_token, n_cur as i32, &[0], true).is_err() {
            return None;
        }
        if ctx.decode(&mut batch).is_err() {
            return None;
        }
        n_cur += 1;

        for _ in 1..self.max_tokens {
            let mut cands = ctx.token_data_array_ith(batch.n_tokens() - 1);
            let next_token = cands.sample_token_greedy();
            if self.model.is_eog_token(next_token) {
                break;
            }
            let piece = self
                .model
                .token_to_piece_bytes(next_token, 32, true, None)
                .ok()?;
            output.push_str(&String::from_utf8_lossy(&piece));

            let trimmed = output.trim().to_lowercase();
            if self.valid_labels.contains(&trimmed) {
                return Some((trimmed, confidence));
            }

            batch.clear();
            if batch.add(next_token, n_cur as i32, &[0], true).is_err() {
                break;
            }
            if ctx.decode(&mut batch).is_err() {
                break;
            }
            n_cur += 1;
        }

        let label = output.trim().to_lowercase();
        if self.valid_labels.contains(&label) {
            Some((label, confidence))
        } else {
            None
        }
    }

    pub fn classify_with_prompt(
        &self,
        input: &str,
        system_prompt: &str,
        valid_labels: &HashSet<String>,
    ) -> Option<String> {
        let raw = self.infer_with_prompt(input, system_prompt)?;
        let label = raw.trim().to_lowercase();
        if valid_labels.contains(&label) {
            Some(label)
        } else {
            warn!(
                "brain: unexpected output '{}' for alt prompt, valid: {:?}",
                label, valid_labels
            );
            None
        }
    }

    fn infer_with_prompt(&self, input: &str, system_prompt: &str) -> Option<String> {
        self.infer_inner(input, system_prompt)
    }

    fn infer(&self, input: &str) -> Option<String> {
        self.infer_inner(input, &self.system_prompt)
    }

    fn infer_inner(&self, input: &str, system_prompt: &str) -> Option<String> {
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(std::num::NonZeroU32::new(self.context_size))
            .with_type_k(KvCacheType::BF16)
            .with_type_v(KvCacheType::BF16);
        let mut ctx = match self.model.new_context(&self.backend, ctx_params) {
            Ok(c) => c,
            Err(e) => {
                warn!("brain: context error: {}", e);
                return None;
            }
        };

        let im_start = self.im_start;
        let im_end = self.im_end;
        let nl = LlamaToken::new(NEWLINE);

        let system_label = self.model.str_to_token("system", AddBos::Never).ok()?;
        let system_text = self.model.str_to_token(system_prompt, AddBos::Never).ok()?;
        let user_label = self.model.str_to_token("user", AddBos::Never).ok()?;
        let user_text = self.model.str_to_token(input, AddBos::Never).ok()?;
        let assistant_label = self.model.str_to_token("assistant", AddBos::Never).ok()?;
        let think_suffix = self
            .model
            .str_to_token("<think>\n\n</think>\n\n", AddBos::Never)
            .ok()?;

        let mut tokens = Vec::new();
        tokens.push(im_start);
        tokens.extend_from_slice(&system_label);
        tokens.push(nl);
        tokens.extend_from_slice(&system_text);
        tokens.push(im_end);
        tokens.push(nl);
        tokens.push(im_start);
        tokens.extend_from_slice(&user_label);
        tokens.push(nl);
        tokens.extend_from_slice(&user_text);
        tokens.push(im_end);
        tokens.push(nl);
        tokens.push(im_start);
        tokens.extend_from_slice(&assistant_label);
        tokens.push(nl);
        tokens.extend_from_slice(&think_suffix);

        let mut batch = LlamaBatch::new(tokens.len(), 1);
        for (i, &token) in tokens.iter().enumerate() {
            let is_last = i == tokens.len() - 1;
            if batch.add(token, i as i32, &[0], is_last).is_err() {
                return None;
            }
        }

        if ctx.decode(&mut batch).is_err() {
            return None;
        }

        let mut output = String::new();
        let mut n_cur = tokens.len();

        for _ in 0..self.max_tokens {
            let mut candidates = ctx.token_data_array_ith(batch.n_tokens() - 1);
            let new_token = candidates.sample_token_greedy();
            if self.model.is_eog_token(new_token) {
                break;
            }
            let piece_bytes = match self.model.token_to_piece_bytes(new_token, 32, true, None) {
                Ok(b) => b,
                Err(_) => break,
            };
            let piece = String::from_utf8_lossy(&piece_bytes);
            output.push_str(&piece);

            let trimmed = output.trim().to_lowercase();
            if self.valid_labels.contains(&trimmed) {
                break;
            }

            batch.clear();
            if batch.add(new_token, n_cur as i32, &[0], true).is_err() {
                break;
            }
            if ctx.decode(&mut batch).is_err() {
                break;
            }
            n_cur += 1;
        }

        if output.trim().is_empty() {
            None
        } else {
            Some(output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brain_config_defaults() {
        let cfg = BrainConfig::new("prompt", &["a", "b"]);
        assert_eq!(cfg.context_size, 512);
        assert_eq!(cfg.max_tokens, 10);
    }

    #[test]
    fn brain_config_builder() {
        let cfg = BrainConfig::new("prompt", &["a"])
            .with_context_size(256)
            .with_max_tokens(5);
        assert_eq!(cfg.context_size, 256);
        assert_eq!(cfg.max_tokens, 5);
    }

    #[test]
    fn load_missing_model_returns_none() {
        let cfg = BrainConfig::new("test", &["yes", "no"]);
        let brain = MicroBrain::load(Path::new("/nonexistent/model.gguf"), cfg);
        assert!(brain.is_none());
    }

    #[test]
    fn load_default_missing_returns_none() {
        let cfg = BrainConfig::new("test", &["yes", "no"]);
        let brain = MicroBrain::load_default("nonexistent-brain-xyz", cfg);
        assert!(brain.is_none());
    }
}
