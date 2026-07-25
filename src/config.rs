use std::sync::LazyLock;

use serde::Deserialize;

/// runtime tunables, loaded once from `CONFIG_PATH` (default ./config.toml);
/// a missing file runs on defaults, a broken file is fatal
pub static CONFIG: LazyLock<AppConfig> = LazyLock::new(load);

const DEFAULT_PATH: &str = "./config.toml";

/// force the lazy config to load and validate; called at startup so a broken
/// file fails fast instead of exploding on the first processed image
pub fn init() {
    LazyLock::force(&CONFIG);
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub detection: DetectionConfig,
    pub cache: CacheConfig,
    pub dino: DinoConfig,
    pub api: ApiConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionConfig {
    /// max Hamming distance (of 64 bits) for whole-image pHash to count as the
    /// same image; calibrated on ./images: re-encoded/distorted copies score
    /// 0-12 across the stage-1 trial views, unrelated pairs 18+
    pub whole_match_threshold: u32,
    /// max Hamming distance for two tiles to count as a match; aligned
    /// re-encoded copies mostly score 0-12 per tile (tails reach ~22),
    /// unrelated tiles sit around 20-40
    pub tile_match_threshold: u32,
    /// tile verdict is only trusted when more informative tiles than this were
    /// compared
    pub min_informative_tiles: u32,
    /// matched-to-informative percentage for a hard match (auto ban)
    pub hard_match_percent: u32,
    /// matched-to-informative percentage to escalate to the admin chat
    pub review_percent: u32,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            whole_match_threshold: 12,
            tile_match_threshold: 13,
            min_informative_tiles: 6,
            hard_match_percent: 75,
            review_percent: 60,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DinoConfig {
    /// shadow mode: embeddings are computed and logged for every scanned
    /// image, similar-but-not-hash-matched images go to the admin channel for
    /// labeling; no ban is ever issued from this stage
    pub enabled: bool,
    /// ONNX file of the DINOv2-S image encoder (see README for the download)
    pub model_path: String,
    /// embedding dataset produced by `anti-scam dino-export`
    pub dataset_path: String,
    /// min cosine similarity against the dataset to post a shadow-review
    /// report; uncalibrated until enough labeled observations are collected
    pub review_threshold: f32,
    /// a card is suppressed unless the best scam similarity beats the best
    /// negative-reference similarity by at least this much
    pub negative_margin: f32,
    /// ONNX Runtime intra-op threads per inference; raise on machines with
    /// cores to spare, embeddings must not starve the hashing pipeline
    pub intra_threads: usize,
    /// labeled card and reference images are saved here as
    /// `<label>/<name>.<ext>` — the pixel corpus for re-exports and eval
    pub captures_dir: String,
}

impl Default for DinoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: "./dinov2s.onnx".to_string(),
            dataset_path: "./dino.json".to_string(),
            review_threshold: 0.6,
            negative_margin: 0.05,
            intra_threads: 2,
            captures_dir: "./dino_captures".to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    /// HTTP endpoint for external image checks; requires the API_JWT_SECRET
    /// env var and a report channel below
    pub enabled: bool,
    /// bind address; keep loopback and put a TLS reverse proxy in front when
    /// exposing publicly
    pub bind: String,
    /// guild the report channel belongs to; recorded with observations
    pub report_guild_id: u64,
    /// channel that receives reports for flagged submissions
    pub report_channel_id: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8080".to_string(),
            report_guild_id: 0,
            report_channel_id: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// how many guilds keep their notification channel in memory
    pub guild_settings_capacity: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { guild_settings_capacity: 100 }
    }
}

fn load() -> AppConfig {
    let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| DEFAULT_PATH.to_string());

    let config = match std::fs::read_to_string(&path) {
        Ok(text) => match parse(&text) {
            Ok(config) => {
                tracing::info!("loaded config from {path}");
                config
            }
            Err(e) => panic!("failed to parse config {path}: {e}"),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("config {path} not found, running on defaults");
            AppConfig::default()
        }
        Err(e) => panic!("failed to read config {path}: {e}"),
    };

    validate(&config);
    config
}

fn parse(text: &str) -> Result<AppConfig, toml::de::Error> {
    toml::from_str(text)
}

fn validate(config: &AppConfig) {
    let detection = &config.detection;

    assert!(
        config.cache.guild_settings_capacity > 0,
        "cache.guild_settings_capacity must be greater than 0"
    );
    assert!(
        detection.hard_match_percent <= 100 && detection.review_percent <= 100,
        "detection percentages must be within 0-100"
    );
    assert!(
        detection.review_percent <= detection.hard_match_percent,
        "detection.review_percent must not exceed detection.hard_match_percent, \
         otherwise the review band is empty"
    );
    assert!(
        config.dino.review_threshold > 0.0 && config.dino.review_threshold <= 1.0,
        "dino.review_threshold must be within (0, 1]"
    );
    assert!(
        (0.0..1.0).contains(&config.dino.negative_margin),
        "dino.negative_margin must be within [0, 1)"
    );
    assert!(config.dino.intra_threads > 0, "dino.intra_threads must be greater than 0");
    if config.api.enabled {
        assert!(
            config.api.report_guild_id != 0 && config.api.report_channel_id != 0,
            "api.enabled requires api.report_guild_id and api.report_channel_id"
        );
    }
}
