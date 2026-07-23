-- shadow-mode observations: one row per scanned image while dino.enabled;
-- "clean" rows build the negative similarity distribution, labels arrive
-- from the admin-channel buttons
CREATE TABLE `dino_observations` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `created_at` TEXT NOT NULL DEFAULT (datetime('now')),
    `guild_id` TEXT NOT NULL,
    `channel_id` TEXT NOT NULL,
    `message_id` TEXT NOT NULL,
    `author_id` TEXT NOT NULL,
    `entry_name` TEXT NOT NULL,
    `similarity` REAL NOT NULL,
    -- what the hashing pipeline said: 'ban' | 'review' | 'clean'
    `hash_verdict` TEXT NOT NULL,
    -- moderator label: 'true_positive' | 'false_positive' | 'hard_negative'
    `label` TEXT,
    `labeled_by` TEXT
);

CREATE INDEX `idx_dino_observations_guild_time`
    ON `dino_observations` (`guild_id`, `created_at`);
