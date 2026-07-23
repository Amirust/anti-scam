use serde::{Deserialize, Serialize};

use crate::Error;
use crate::images::{self, TileGrid, HASH_BYTES, TILE_COUNT};

/// schema of the config file
pub const FORMAT_VERSION: u32 = 1;
pub const PIPELINE_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct ImageData {
    pub name: String,
    pub whole_hash: [u8; HASH_BYTES],
    pub grid: TileGrid,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub format_version: u32,
    pub pipeline_version: u32,
    pub entries: Vec<ConfigEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigEntry {
    pub name: String,
    /// 8 bytes hex encoded
    pub whole_hash: String,
    /// 16 tiles, 8 bytes hex encoded each
    pub tile_hashes: Vec<String>,
    pub informative: Vec<bool>,
}

/// banned config path from env (BANNED_CONFIG, default ./banned.json)
pub fn dataset_path() -> String {
    std::env::var("BANNED_CONFIG").unwrap_or_else(|_| "./banned.json".to_string())
}

/// a missing file is a warning + empty database, a broken file is fatal
pub fn load_startup_db() -> Vec<ImageData> {
    let path = dataset_path();

    if !std::path::Path::new(&path).exists() {
        tracing::warn!("banned image config {path} not found, starting with an EMPTY database");
        return Vec::new();
    }

    match load(&path) {
        Ok(entries) => {
            tracing::info!("loaded {} banned image entr(ies) from {path}", entries.len());
            entries
        }
        Err(e) => panic!("failed to load banned image config {path}: {e}"),
    }
}

pub fn load(path: &str) -> Result<Vec<ImageData>, Error> {
    let json = std::fs::read_to_string(path)?;
    parse(&json)
}

pub fn parse(json: &str) -> Result<Vec<ImageData>, Error> {
    let config: Config = serde_json::from_str(json)?;

    if config.format_version != FORMAT_VERSION {
        return Err(format!(
            "config format v{} is not supported, this build expects v{FORMAT_VERSION}",
            config.format_version
        )
        .into());
    }
    if config.pipeline_version != PIPELINE_VERSION {
        return Err(format!(
            "config was built by hashing pipeline v{}, this build runs v{PIPELINE_VERSION}; \
             download a matching config or regenerate it with `anti-scam export`",
            config.pipeline_version
        )
        .into());
    }

    config.entries.iter().map(parse_entry).collect()
}

fn parse_entry(entry: &ConfigEntry) -> Result<ImageData, Error> {
    let context = |what: &str| format!("entry \"{}\": {what}", entry.name);

    if entry.tile_hashes.len() != TILE_COUNT {
        return Err(context(&format!(
            "expected {TILE_COUNT} tile hashes, got {}",
            entry.tile_hashes.len()
        ))
        .into());
    }
    if entry.informative.len() != TILE_COUNT {
        return Err(context(&format!(
            "expected {TILE_COUNT} informative flags, got {}",
            entry.informative.len()
        ))
        .into());
    }

    let whole_hash = hex_decode(&entry.whole_hash).map_err(|e| context(&e))?;
    let tile_hashes: Vec<[u8; HASH_BYTES]> = entry
        .tile_hashes
        .iter()
        .map(|h| hex_decode(h).map_err(|e| context(&e)))
        .collect::<Result<_, _>>()?;

    let hashes: [[u8; HASH_BYTES]; TILE_COUNT] = tile_hashes
        .try_into()
        .map_err(|_| context("unexpected tile hash count"))?;
    let informative: [bool; TILE_COUNT] = entry
        .informative
        .clone()
        .try_into()
        .map_err(|_| context("unexpected informative flag count"))?;

    Ok(ImageData {
        name: entry.name.clone(),
        whole_hash,
        grid: TileGrid { hashes, informative },
    })
}

/// run raw image bytes through the full hashing pipeline
pub fn image_data_from_bytes(name: &str, bytes: &[u8]) -> Result<ImageData, Error> {
    let normalized = images::normalize_image(bytes)?;
    let whole_hash = images::whole_image_hash(&normalized)?;
    let grid = images::get_hash_grid(&normalized)?;

    Ok(ImageData {
        name: name.to_string(),
        whole_hash,
        grid,
    })
}

pub fn to_json(entries: &[ImageData]) -> Result<String, Error> {
    let config = Config {
        format_version: FORMAT_VERSION,
        pipeline_version: PIPELINE_VERSION,
        entries: entries.iter().map(to_config_entry).collect(),
    };

    Ok(serde_json::to_string_pretty(&config)?)
}

fn to_config_entry(data: &ImageData) -> ConfigEntry {
    ConfigEntry {
        name: data.name.clone(),
        whole_hash: hex_encode(&data.whole_hash),
        tile_hashes: data.grid.hashes.iter().map(|h| hex_encode(h)).collect(),
        informative: data.grid.informative.to_vec(),
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<[u8; HASH_BYTES], String> {
    if !s.is_ascii() || s.len() != HASH_BYTES * 2 {
        return Err(format!(
            "expected {} hex chars, got \"{s}\"",
            HASH_BYTES * 2
        ));
    }

    let bytes: Vec<u8> = (0..HASH_BYTES)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("invalid hex in \"{s}\""))
        })
        .collect::<Result<_, _>>()?;

    bytes
        .try_into()
        .map_err(|_| format!("invalid hex length in \"{s}\""))
}