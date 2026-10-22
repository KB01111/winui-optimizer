//! Registry of local models and runtimes available on this machine.
//!
//! The mock model is always available. ONNX and NPU entries are explicit
//! placeholders: no ONNX/NPU runtime is bundled (and no runtime dependency is
//! added), so they report `available = false` until a validated runtime
//! implementation flips them on.

use serde::{Deserialize, Serialize};

/// Kind of local model runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalModelKind {
    /// Deterministic built-in heuristic model.
    Mock,
    /// Real ONNX model via an ONNX runtime (extensibility placeholder).
    Onnx,
    /// Vendor NPU runtime (extensibility placeholder).
    Npu,
}

/// One registry entry, safe to show in the UI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalModelEntry {
    /// Stable registry name.
    pub name: String,
    /// Model/runtime identifier reported on results.
    pub model_id: String,
    /// Runtime family.
    pub kind: LocalModelKind,
    /// True only when the runtime is bundled and validated.
    pub available: bool,
    /// Explanation for the UI (especially when not available).
    pub note: String,
}

/// Lists the local models known to this build.
#[derive(Debug, Clone)]
pub struct LocalModelRegistry {
    entries: Vec<LocalModelEntry>,
}

impl Default for LocalModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalModelRegistry {
    /// Build the registry: mock model available, ONNX/NPU placeholders not.
    pub fn new() -> Self {
        Self {
            entries: vec![
                LocalModelEntry {
                    name: "local-mock".to_string(),
                    model_id: crate::model::MockLocalDecisionModel::MODEL_ID.to_string(),
                    kind: LocalModelKind::Mock,
                    available: true,
                    note: "deterministic heuristic model with no weights; always available and never uses the network"
                        .to_string(),
                },
                LocalModelEntry {
                    name: "onnx".to_string(),
                    model_id: "onnx-runtime".to_string(),
                    kind: LocalModelKind::Onnx,
                    available: false,
                    note: "placeholder: no ONNX runtime is bundled with this build; implement a validated runtime before enabling"
                        .to_string(),
                },
                LocalModelEntry {
                    name: "npu".to_string(),
                    model_id: "npu-runtime".to_string(),
                    kind: LocalModelKind::Npu,
                    available: false,
                    note: "placeholder: NPU inference requires a validated vendor runtime; a driver registry hint alone is never enough"
                        .to_string(),
                },
            ],
        }
    }

    /// All entries.
    pub fn list(&self) -> &[LocalModelEntry] {
        &self.entries
    }

    /// Only the entries that are actually usable.
    pub fn available(&self) -> Vec<&LocalModelEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.available)
            .collect()
    }

    /// Look up one entry by registry name.
    pub fn get(&self, name: &str) -> Option<&LocalModelEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// True when the named model is usable.
    pub fn is_available(&self, name: &str) -> bool {
        self.get(name).map(|entry| entry.available).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_is_always_available_placeholders_are_not() {
        let registry = LocalModelRegistry::new();
        assert!(registry.is_available("local-mock"));
        assert!(!registry.is_available("onnx"));
        assert!(!registry.is_available("npu"));
        assert!(!registry.is_available("does-not-exist"));
        assert_eq!(registry.available().len(), 1);

        let npu = registry.get("npu").unwrap();
        assert_eq!(npu.kind, LocalModelKind::Npu);
        assert!(npu.note.contains("validated"));
    }

    #[test]
    fn entries_serialize_camel_case() {
        let registry = LocalModelRegistry::new();
        let value = serde_json::to_value(registry.list()).unwrap();
        assert!(value[0].get("modelId").is_some());
        assert_eq!(value[0]["kind"], "mock");
        assert_eq!(value[0]["available"], true);
    }

    #[test]
    fn registry_lists_three_entries() {
        let registry = LocalModelRegistry::new();
        assert_eq!(registry.list().len(), 3);
        assert!(registry.get("local-mock").is_some());
        assert!(registry.get("onnx").is_some());
        assert!(registry.get("npu").is_some());
    }
}
