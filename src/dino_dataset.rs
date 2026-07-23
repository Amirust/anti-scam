use serde::{Deserialize, Serialize};

use crate::Error;
use crate::dino::{self, EMBEDDING_DIM};

/// schema of the embedding dataset file
pub const FORMAT_VERSION: u32 = 1;
/// bound to how embeddings are computed (model file, input size, resize
/// filter, normalization, token choice); bump on any change and regenerate
/// the dataset with `anti-scam dino-export`
pub const PIPELINE_VERSION: u32 = 1;
/// human-readable provenance stored in the file, not validated
pub const MODEL_DESCRIPTION: &str =
    "Xenova/dinov2-small onnx fp32, 224x224 resize_exact lanczos3, imagenet norm, CLS, L2";

#[derive(Debug, Clone)]
pub struct DinoEntry {
    pub name: String,
    /// L2-normalized, EMBEDDING_DIM long
    pub embedding: Vec<f32>,
}

#[derive(Serialize, Deserialize)]
struct DinoFile {
    format_version: u32,
    pipeline_version: u32,
    model: String,
    entries: Vec<DinoFileEntry>,
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

pub fn load(path: &str) -> Result<Vec<DinoEntry>, Error> {
    let json = std::fs::read_to_string(path)?;
    parse(&json)
}

pub fn parse(json: &str) -> Result<Vec<DinoEntry>, Error> {
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

    file.entries.into_iter().map(parse_entry).collect()
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

pub fn to_json(entries: &[DinoEntry]) -> Result<String, Error> {
    let file = DinoFile {
        format_version: FORMAT_VERSION,
        pipeline_version: PIPELINE_VERSION,
        model: MODEL_DESCRIPTION.to_string(),
        entries: entries
            .iter()
            .map(|entry| DinoFileEntry {
                name: entry.name.clone(),
                embedding: entry.embedding.clone(),
            })
            .collect(),
    };

    Ok(serde_json::to_string(&file)?)
}

/// highest-cosine reference for an incoming embedding
pub fn best_match<'a>(embedding: &[f32], entries: &'a [DinoEntry]) -> Option<(&'a DinoEntry, f32)> {
    entries
        .iter()
        .map(|entry| (entry, dino::cosine_similarity(embedding, &entry.embedding)))
        .max_by(|(_, a), (_, b)| a.total_cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_embedding(hot_index: usize) -> Vec<f32> {
        (0..EMBEDDING_DIM)
            .map(|i| if i == hot_index { 1.0 } else { 0.0 })
            .collect()
    }

    #[test]
    fn dataset_round_trips_through_json() {
        let entries = vec![DinoEntry {
            name: "mr_beast_1".to_string(),
            embedding: unit_embedding(0),
        }];

        let json = to_json(&entries).unwrap();
        let parsed = parse(&json).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "mr_beast_1");
        assert_eq!(parsed[0].embedding, entries[0].embedding);
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
    fn best_match_picks_the_closest_entry() {
        let entries = vec![
            DinoEntry { name: "far".to_string(), embedding: unit_embedding(1) },
            DinoEntry { name: "near".to_string(), embedding: unit_embedding(0) },
        ];

        let (best, similarity) = best_match(&unit_embedding(0), &entries).unwrap();

        assert_eq!(best.name, "near");
        assert!((similarity - 1.0).abs() < 1e-6);
    }

    #[test]
    fn best_match_of_empty_dataset_is_none() {
        assert!(best_match(&unit_embedding(0), &[]).is_none());
    }
}
