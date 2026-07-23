use std::sync::{Arc, RwLock};

use crate::detection::{self, Verdict};
use crate::img_config::{self, ImageData};
use crate::{images, Error};

/// length of the sha256 hex prefix used to name manually added entries
const MANUAL_NAME_HEX_CHARS: usize = 8;
/// keep entry names embed and audit-log-friendly
const MAX_NAME_LENGTH: usize = 64;

pub struct Dataset {
    path: String,
    entries: RwLock<Arc<Vec<ImageData>>>,
    write_lock: tokio::sync::Mutex<()>,
}

pub enum AddOutcome {
    Added { name: String },
    AlreadyMatches { name: String },
    NameTaken { name: String },
}

enum AddPrep {
    Duplicate(String),
    New(ImageData),
}

impl Dataset {
    pub fn load_startup() -> Self {
        Self::new(img_config::dataset_path(), img_config::load_startup_db())
    }

    fn new(path: String, entries: Vec<ImageData>) -> Self {
        Self {
            path,
            entries: RwLock::new(Arc::new(entries)),
            write_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn snapshot(&self) -> Arc<Vec<ImageData>> {
        self.entries.read().unwrap().clone()
    }

    pub async fn add_image(
        &self,
        bytes: bytes::Bytes,
        custom_name: Option<String>,
    ) -> Result<AddOutcome, Error> {
        let _guard = self.write_lock.lock().await;
        let snapshot = self.snapshot();

        let sha_hex = img_config::hex_encode(&images::sha256_hash(&bytes));
        let name = match normalize_name(custom_name) {
            Some(name) => name,
            None => format!("manual_{}", &sha_hex[..MANUAL_NAME_HEX_CHARS]),
        };

        if name.len() > MAX_NAME_LENGTH {
            return Err(format!("entry name is longer than {MAX_NAME_LENGTH} characters").into());
        }

        let prep = tokio::task::spawn_blocking({
            let snapshot = Arc::clone(&snapshot);
            let name = name.clone();
            move || -> Result<AddPrep, Error> {
                if let Verdict::Ban { entry_name, .. } =
                    detection::classify_image(&bytes, &snapshot)?
                {
                    return Ok(AddPrep::Duplicate(entry_name));
                }
                Ok(AddPrep::New(img_config::image_data_from_bytes(&name, &bytes)?))
            }
        })
        .await??;

        let entry = match prep {
            AddPrep::Duplicate(existing) => {
                return Ok(AddOutcome::AlreadyMatches { name: existing });
            }
            AddPrep::New(entry) => entry,
        };

        // after the duplicate scan: an identical image must report AlreadyMatches, not a collision with its own auto name
        if snapshot.iter().any(|existing| existing.name == entry.name) {
            return Ok(AddOutcome::NameTaken { name });
        }

        let mut entries: Vec<ImageData> = snapshot.as_ref().clone();
        entries.push(entry);

        write_atomically(&self.path, &img_config::to_json(&entries)?)?;
        *self.entries.write().unwrap() = Arc::new(entries);

        tracing::info!("dataset entry \"{name}\" added, {} entries total", self.snapshot().len());
        Ok(AddOutcome::Added { name })
    }
}

fn normalize_name(name: Option<String>) -> Option<String> {
    name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty())
}

/// write via a temp file + rename so a crash mid-write cannot corrupt the json
fn write_atomically(path: &str, contents: &str) -> Result<(), Error> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
