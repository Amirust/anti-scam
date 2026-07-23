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
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionConfig {
    /// max Hamming distance (of 64 bits) for whole-image pHash to count as the
    /// same image; calibrated on ./images: re-encoded copies score 0-6,
    /// unrelated pairs 18+
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
            whole_match_threshold: 10,
            tile_match_threshold: 13,
            min_informative_tiles: 6,
            hard_match_percent: 75,
            review_percent: 60,
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
}
