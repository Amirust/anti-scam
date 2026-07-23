use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;
use sqlx::sqlite::SqliteConnectOptions;

use crate::config::CONFIG;

/// guild_id -> notification_channel_id; `None` remembers "no settings row",
/// so unconfigured guilds don't hit sqlite on every image either
type ChannelCache = Mutex<LruCache<String, Option<String>>>;

pub struct Database {
    pool: sqlx::SqlitePool,
    channel_cache: ChannelCache,
}

/// one shadow-mode measurement, written for every scanned image
pub struct DinoObservation {
    pub guild_id: String,
    pub channel_id: String,
    pub message_id: String,
    pub author_id: String,
    pub entry_name: String,
    pub similarity: f64,
    pub best_negative_similarity: Option<f64>,
    pub hash_verdict: &'static str,
}

impl Database {
    pub async fn new() -> Result<Self, sqlx::Error> {
        let pool = sqlx::SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename("data.db")
                .create_if_missing(true)
        ).await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self::with_pool(pool))
    }

    fn with_pool(pool: sqlx::SqlitePool) -> Self {
        // validated non-zero at startup by config::init
        let capacity = NonZeroUsize::new(CONFIG.cache.guild_settings_capacity)
            .expect("cache.guild_settings_capacity must be non-zero");

        Self {
            pool,
            channel_cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub async fn get_notification_channel(
        &self,
        guild_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        if let Some(cached) = self.channel_cache.lock().unwrap().get(guild_id) {
            return Ok(cached.clone());
        }

        let channel: Option<String> = sqlx::query_scalar(
            "SELECT notification_channel_id FROM settings WHERE guild_id = ?",
        )
        .bind(guild_id)
        .fetch_optional(&self.pool)
        .await?;

        self.channel_cache
            .lock()
            .unwrap()
            .put(guild_id.to_string(), channel.clone());

        Ok(channel)
    }

    pub async fn set_settings(
        &self,
        guild_id: &str,
        notification_channel_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "
                INSERT INTO settings (guild_id, notification_channel_id) VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    notification_channel_id = excluded.notification_channel_id",
        )
        .bind(guild_id)
        .bind(notification_channel_id)
        .execute(&self.pool)
        .await?;

        // write-through: a stale cached value must not outlive the update
        self.channel_cache
            .lock()
            .unwrap()
            .put(guild_id.to_string(), Some(notification_channel_id.to_string()));

        Ok(())
    }

    pub async fn insert_dino_observation(
        &self,
        observation: &DinoObservation,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            "
                INSERT INTO dino_observations
                    (guild_id, channel_id, message_id, author_id,
                     entry_name, similarity, best_negative_similarity, hash_verdict)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&observation.guild_id)
        .bind(&observation.channel_id)
        .bind(&observation.message_id)
        .bind(&observation.author_id)
        .bind(&observation.entry_name)
        .bind(observation.similarity)
        .bind(observation.best_negative_similarity)
        .bind(observation.hash_verdict)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// first label wins: returns false when the observation is unknown or
    /// already labeled (two moderators racing on the same card)
    pub async fn set_dino_label(
        &self,
        observation_id: i64,
        label: &str,
        labeled_by: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE dino_observations SET label = ?, labeled_by = ?
             WHERE id = ? AND label IS NULL",
        )
        .bind(label)
        .bind(labeled_by)
        .bind(observation_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }
}
