use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::dino::{self, EMBEDDING_DIM};
use crate::utils::write_atomically;

/// schema of the embedding dataset file
pub const FORMAT_VERSION: u32 = 1;
/// bound to how embeddings are computed (model file, input size, resize
/// filter, normalization, token choice); bump on any change and regenerate
/// the dataset with `anti-scam dino-export`
pub const PIPELINE_VERSION: u32 = 1;
/// human-readable provenance stored in the file, not validated
pub const MODEL_DESCRIPTION: &str =
    "Xenova/dinov2-small onnx fp32, 224x224 resize_exact lanczos3, imagenet norm, CLS, L2";

/// runtime additions this close to an existing reference are duplicates
const DUPLICATE_SIMILARITY: f32 = 0.995;

#[derive(Debug, Clone)]
pub struct DinoEntry {
    pub name: String,
    /// L2-normalized, EMBEDDING_DIM long
    pub embedding: Vec<f32>,
}

/// scam references drive matching; negative references are known legit
/// look-alikes that suppress cards via the margin rule
#[derive(Debug, Default, Clone)]
pub struct DinoRefs {
    pub scams: Vec<DinoEntry>,
    pub negatives: Vec<DinoEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    Scam,
    Negative,
}

impl RefKind {
    pub fn describe(self) -> &'static str {
        match self {
            RefKind::Scam => "scam reference",
            RefKind::Negative => "negative reference",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct DinoFile {
    format_version: u32,
    pipeline_version: u32,
    model: String,
    entries: Vec<DinoFileEntry>,
    #[serde(default)]
    negatives: Vec<DinoFileEntry>,
}

#[derive(Serialize, Deserialize)]
struct DinoFileEntry {
    name: String,
    embedding: Vec<f32>,
}

/// the caller decides whether a missing dataset is fatal
pub fn is_not_found(error: &Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}

pub fn load(path: &str) -> Result<DinoRefs, Error> {
    let json = std::fs::read_to_string(path)?;
    parse(&json)
}

pub fn parse(json: &str) -> Result<DinoRefs, Error> {
    let file: DinoFile = serde_json::from_str(json)?;

    if file.format_version != FORMAT_VERSION {
        return Err(format!(
            "dino dataset format v{} is not supported, this build expects v{FORMAT_VERSION}",
            file.format_version
        )
        .into());
    }
    if file.pipeline_version != PIPELINE_VERSION {
        return Err(format!(
            "dino dataset was built by embedding pipeline v{}, this build runs \
             v{PIPELINE_VERSION}; regenerate it with `anti-scam dino-export`",
            file.pipeline_version
        )
        .into());
    }

    let refs = DinoRefs {
        scams: file.entries.into_iter().map(parse_entry).collect::<Result<_, _>>()?,
        negatives: file.negatives.into_iter().map(parse_entry).collect::<Result<_, _>>()?,
    };

    if let Some(duplicate) = first_duplicate_name(&refs) {
        return Err(format!("dino dataset has a duplicate entry name \"{duplicate}\"").into());
    }
    Ok(refs)
}

fn parse_entry(entry: DinoFileEntry) -> Result<DinoEntry, Error> {
    if entry.name.is_empty() {
        return Err("dino dataset entry with an empty name".into());
    }
    if entry.embedding.len() != EMBEDDING_DIM {
        return Err(format!(
            "entry \"{}\": expected {EMBEDDING_DIM} embedding values, got {}",
            entry.name,
            entry.embedding.len()
        )
        .into());
    }
    if entry.embedding.iter().any(|v| !v.is_finite()) {
        return Err(format!("entry \"{}\": embedding has non-finite values", entry.name).into());
    }

    Ok(DinoEntry {
        name: entry.name,
        embedding: entry.embedding,
    })
}

pub fn to_json(refs: &DinoRefs) -> Result<String, Error> {
    let file = DinoFile {
        format_version: FORMAT_VERSION,
        pipeline_version: PIPELINE_VERSION,
        model: MODEL_DESCRIPTION.to_string(),
        entries: refs.scams.iter().map(to_file_entry).collect(),
        negatives: refs.negatives.iter().map(to_file_entry).collect(),
    };

    Ok(serde_json::to_string(&file)?)
}

fn to_file_entry(entry: &DinoEntry) -> DinoFileEntry {
    DinoFileEntry {
        name: entry.name.clone(),
        embedding: entry.embedding.clone(),
    }
}

/// entry names are unique across both lists so log lines and card texts are
/// unambiguous
pub fn first_duplicate_name(refs: &DinoRefs) -> Option<&str> {
    let mut seen = std::collections::HashSet::new();
    refs.scams
        .iter()
        .chain(&refs.negatives)
        .find(|entry| !seen.insert(entry.name.as_str()))
        .map(|entry| entry.name.as_str())
}

/// highest-cosine reference for an incoming embedding
pub fn best_match<'a>(embedding: &[f32], entries: &'a [DinoEntry]) -> Option<(&'a DinoEntry, f32)> {
    entries
        .iter()
        .map(|entry| (entry, dino::cosine_similarity(embedding, &entry.embedding)))
        .max_by(|(_, a), (_, b)| a.total_cmp(b))
}

pub enum DinoAddOutcome {
    Added { name: String },
    NearDuplicate { name: String, similarity: f32 },
    NameTaken { name: String },
}

impl DinoAddOutcome {
    pub fn describe(&self, kind: RefKind) -> String {
        let kind = kind.describe();
        match self {
            DinoAddOutcome::Added { name } => format!("Added as {kind} `{name}`."),
            DinoAddOutcome::NearDuplicate { name, similarity } => format!(
                "Not added: nearly identical to existing entry `{name}` \
                 (cosine {similarity:.4})."
            ),
            DinoAddOutcome::NameTaken { name } => {
                format!("The name `{name}` is already used by another entry, pick a different one.")
            }
        }
    }
}

/// mutable runtime view of the dataset, same discipline as `dataset::Dataset`:
/// lock-free reads via an Arc snapshot, serialized atomic writes
pub struct DinoStore {
    path: String,
    refs: RwLock<Arc<DinoRefs>>,
    write_lock: tokio::sync::Mutex<()>,
}

impl DinoStore {
    pub fn new(path: String, refs: DinoRefs) -> Self {
        Self {
            path,
            refs: RwLock::new(Arc::new(refs)),
            write_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn snapshot(&self) -> Arc<DinoRefs> {
        self.refs.read().unwrap().clone()
    }

    pub async fn add(
        &self,
        kind: RefKind,
        name: String,
        embedding: Vec<f32>,
    ) -> Result<DinoAddOutcome, Error> {
        let _guard = self.write_lock.lock().await;
        let snapshot = self.snapshot();

        let same_kind = match kind {
            RefKind::Scam => &snapshot.scams,
            RefKind::Negative => &snapshot.negatives,
        };
        if let Some((existing, similarity)) = best_match(&embedding, same_kind)
            && similarity >= DUPLICATE_SIMILARITY
        {
            return Ok(DinoAddOutcome::NearDuplicate {
                name: existing.name.clone(),
                similarity,
            });
        }
        if snapshot.scams.iter().chain(&snapshot.negatives).any(|entry| entry.name == name) {
            return Ok(DinoAddOutcome::NameTaken { name });
        }

        let entry = DinoEntry { name: name.clone(), embedding };
        let refs = match kind {
            RefKind::Scam => DinoRefs {
                scams: with_entry(&snapshot.scams, entry),
                negatives: snapshot.negatives.clone(),
            },
            RefKind::Negative => DinoRefs {
                scams: snapshot.scams.clone(),
                negatives: with_entry(&snapshot.negatives, entry),
            },
        };

        write_atomically(&self.path, &to_json(&refs)?)?;
        *self.refs.write().unwrap() = Arc::new(refs);

        tracing::info!("dino {} \"{name}\" added to {}", kind.describe(), self.path);
        Ok(DinoAddOutcome::Added { name })
    }
}

fn with_entry(entries: &[DinoEntry], entry: DinoEntry) -> Vec<DinoEntry> {
    entries.iter().cloned().chain(std::iter::once(entry)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_embedding(hot_index: usize) -> Vec<f32> {
        (0..EMBEDDING_DIM)
            .map(|i| if i == hot_index { 1.0 } else { 0.0 })
            .collect()
    }

    fn entry(name: &str, hot_index: usize) -> DinoEntry {
        DinoEntry { name: name.to_string(), embedding: unit_embedding(hot_index) }
    }

    fn temp_store(test_name: &str, refs: DinoRefs) -> DinoStore {
        let path = std::env::temp_dir().join(format!("anti-scam-dino-{test_name}.json"));
        DinoStore::new(path.to_string_lossy().into_owned(), refs)
    }

    #[test]
    fn dataset_round_trips_through_json() {
        let refs = DinoRefs {
            scams: vec![entry("mr_beast_1", 0)],
            negatives: vec![entry("legit_screen", 1)],
        };

        let parsed = parse(&to_json(&refs).unwrap()).unwrap();

        assert_eq!(parsed.scams.len(), 1);
        assert_eq!(parsed.scams[0].name, "mr_beast_1");
        assert_eq!(parsed.negatives.len(), 1);
        assert_eq!(parsed.negatives[0].name, "legit_screen");
    }

    #[test]
    fn parse_accepts_files_without_negatives_field() {
        let json = format!(
            r#"{{"format_version":{FORMAT_VERSION},"pipeline_version":{PIPELINE_VERSION},
                "model":"x","entries":[]}}"#
        );

        let parsed = parse(&json).unwrap();

        assert!(parsed.scams.is_empty());
        assert!(parsed.negatives.is_empty());
    }

    #[test]
    fn parse_rejects_pipeline_version_mismatch() {
        let json = format!(
            r#"{{"format_version":{FORMAT_VERSION},"pipeline_version":{},"model":"x","entries":[]}}"#,
            PIPELINE_VERSION + 1
        );

        let error = parse(&json).unwrap_err().to_string();

        assert!(error.contains("embedding pipeline"), "unexpected error: {error}");
    }

    #[test]
    fn parse_rejects_wrong_embedding_length() {
        let json = format!(
            r#"{{"format_version":{FORMAT_VERSION},"pipeline_version":{PIPELINE_VERSION},"model":"x",
                "entries":[{{"name":"a","embedding":[1.0,2.0]}}]}}"#
        );

        let error = parse(&json).unwrap_err().to_string();

        assert!(error.contains("embedding values"), "unexpected error: {error}");
    }

    #[test]
    fn parse_rejects_duplicate_names_across_lists() {
        let refs = DinoRefs {
            scams: vec![entry("same", 0)],
            negatives: vec![entry("same", 1)],
        };

        let error = parse(&to_json(&refs).unwrap()).unwrap_err().to_string();

        assert!(error.contains("duplicate"), "unexpected error: {error}");
    }

    #[test]
    fn best_match_picks_the_closest_entry() {
        let entries = vec![entry("far", 1), entry("near", 0)];

        let (best, similarity) = best_match(&unit_embedding(0), &entries).unwrap();

        assert_eq!(best.name, "near");
        assert!((similarity - 1.0).abs() < 1e-6);
    }

    #[test]
    fn best_match_of_empty_dataset_is_none() {
        assert!(best_match(&unit_embedding(0), &[]).is_none());
    }

    #[tokio::test]
    async fn store_add_rejects_near_duplicates_of_same_kind() {
        let store = temp_store(
            "dup",
            DinoRefs { scams: vec![entry("existing", 0)], negatives: vec![] },
        );

        let outcome = store
            .add(RefKind::Scam, "fresh".to_string(), unit_embedding(0))
            .await
            .unwrap();

        assert!(matches!(outcome, DinoAddOutcome::NearDuplicate { name, .. } if name == "existing"));
    }

    #[tokio::test]
    async fn store_add_rejects_taken_names_across_kinds() {
        let store = temp_store(
            "name",
            DinoRefs { scams: vec![entry("taken", 0)], negatives: vec![] },
        );

        let outcome = store
            .add(RefKind::Negative, "taken".to_string(), unit_embedding(5))
            .await
            .unwrap();

        assert!(matches!(outcome, DinoAddOutcome::NameTaken { .. }));
    }

    #[tokio::test]
    async fn store_add_appends_and_persists() {
        let store = temp_store("append", DinoRefs::default());

        let outcome = store
            .add(RefKind::Negative, "legit".to_string(), unit_embedding(2))
            .await
            .unwrap();

        assert!(matches!(outcome, DinoAddOutcome::Added { .. }));
        assert_eq!(store.snapshot().negatives.len(), 1);
    }
}
