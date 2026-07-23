-- Add migration script here
CREATE TABLE `settings` (
    `guild_id` text PRIMARY KEY NOT NULL,
    `notification_channel_id` text NOT NULL
);