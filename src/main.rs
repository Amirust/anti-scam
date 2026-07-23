mod commands;
mod config;
mod dataset;
mod events;
mod detection;
mod export;
mod images;
mod img_config;
mod interactions;
mod db;
mod embeds;
mod utils;

use std::collections::HashSet;
use std::env::var;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use poise::serenity_prelude as serenity;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

type InflightKey = ([u8; 32], u64);
/// sha256 hashes of images currently being processed
type InflightSet = Arc<Mutex<HashSet<InflightKey>>>;

struct Data {
    inflight: InflightSet,
    http: reqwest::Client,
    // banned image dataset, hot-swappable via the "Add to dataset" button
    scam_db: Arc<dataset::Dataset>,
    db: Arc<db::Database>,
}
type Error = Box<dyn std::error::Error + Send + Sync>;
type Context<'a> = poise::Context<'a, Data, Error>;

async fn on_error(error: poise::FrameworkError<'_, Data, Error>) {
    match error {
        poise::FrameworkError::Setup { error, .. } => panic!("Failed to start bot: {:?}", error),
        poise::FrameworkError::Command { error, ctx, .. } => {
            tracing::error!("Error in command `{}`: {:?}", ctx.command().name, error);
        }
        error => {
            if let Err(e) = poise::builtins::on_error(error).await {
                tracing::error!("Error while handling error: {}", e)
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|a| a == "export") {
        return export::run(&args[2..]);
    }

    // fail fast on a broken config.toml instead of on the first image
    config::init();

    let db = Arc::new(db::Database::new().await.expect("failed to open database"));
    let scam_db = Arc::new(dataset::Dataset::load_startup());

    let options = poise::FrameworkOptions {
        commands: vec![
            commands::settings(),
            commands::set_notification_channel(),
            commands::add_image_to_dataset()
        ],
        on_error: |error| Box::pin(on_error(error)),

        pre_command: |ctx| {
            Box::pin(async move {
                tracing::info!("Executing command {}...", ctx.command().qualified_name);
            })
        },
        post_command: |ctx| {
            Box::pin(async move {
                tracing::info!("Executed command {}!", ctx.command().qualified_name);
            })
        },
        event_handler: |ctx, event, framework, data| {
            Box::pin(async move {
                events::handle_event(ctx, event, framework, data).await
            })
        },
        ..Default::default()
    };

    let framework = poise::Framework::builder()
        .setup(move |ctx, ready, framework| {
            Box::pin(async move {
                tracing::info!("Logged in as {}", ready.user.name);
                poise::builtins::register_globally(ctx, &framework.options().commands).await?;

                Ok(Data {
                    inflight: Arc::new(Mutex::new(HashSet::new())),
                    http: reqwest::Client::builder()
                        .timeout(HTTP_TIMEOUT)
                        .build()?,
                    db,
                    scam_db,
                })
            })
        })
        .options(options)
        .build();

    let token = var("DISCORD_TOKEN")
        .expect("Missing `DISCORD_TOKEN` env var, see README for more information.");

    let intents =
        serenity::GatewayIntents::non_privileged() |
        serenity::GatewayIntents::MESSAGE_CONTENT  |
        serenity::GatewayIntents::GUILD_MESSAGES;

    let client = serenity::ClientBuilder::new(token, intents)
        .framework(framework)
        .await;

    client
        .expect("failed to build Discord client")
        .start()
        .await
        .expect("Discord client crashed")
}