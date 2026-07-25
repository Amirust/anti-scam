use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::post;
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serenity::all::{ChannelId, CreateAttachment, CreateMessage};

use crate::config::CONFIG;
use crate::dataset::Dataset;
use crate::db::{Database, DinoObservation};
use crate::dino::DinoRuntime;
use crate::embeds::get_api_report_embed;
use crate::events::MAX_ATTACHMENT_BYTES;
use crate::{Error, detection, dino_shadow, images, img_config, interactions};

const SECRET_ENV: &str = "API_JWT_SECRET";
/// HS256 secrets shorter than this are brute-forceable
const MIN_SECRET_LENGTH: usize = 32;
/// submissions processed concurrently or queued; each one costs an inference,
/// so a flood must hit 429 instead of pinning the CPU
const MAX_IN_FLIGHT: usize = 32;
const DEFAULT_TOKEN_DAYS: u64 = 365;
const SECONDS_PER_DAY: u64 = 86_400;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// client name; shows up in reports and logs
    sub: String,
    iat: u64,
    exp: u64,
}

struct ApiState {
    http: Arc<serenity::http::Http>,
    db: Arc<Database>,
    scam_db: Arc<Dataset>,
    dino: Option<Arc<DinoRuntime>>,
    decoding_key: DecodingKey,
    limiter: Arc<tokio::sync::Semaphore>,
}

/// bind the listener (fail fast on a bad address) and serve in a background
/// task; the secret is validated here so a misconfigured API cannot start
pub async fn start(
    discord_token: &str,
    db: Arc<Database>,
    scam_db: Arc<Dataset>,
    dino: Option<Arc<DinoRuntime>>,
) {
    let secret = load_secret();
    let state = Arc::new(ApiState {
        http: Arc::new(serenity::http::Http::new(discord_token)),
        db,
        scam_db,
        dino,
        decoding_key: DecodingKey::from_secret(secret.as_bytes()),
        limiter: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
    });

    let app = Router::new()
        .route("/v1/check", post(check))
        .layer(DefaultBodyLimit::max(MAX_ATTACHMENT_BYTES as usize))
        .with_state(state);

    let bind = &CONFIG.api.bind;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .unwrap_or_else(|e| panic!("api cannot bind {bind}: {e}"));
    tracing::info!("api listening on {bind}");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("api server stopped: {e}");
        }
    });
}

fn load_secret() -> String {
    let secret = std::env::var(SECRET_ENV).unwrap_or_else(|_| {
        panic!("api.enabled requires the {SECRET_ENV} env var (mint tokens with `anti-scam issue-token`)")
    });
    assert!(
        secret.len() >= MIN_SECRET_LENGTH,
        "{SECRET_ENV} must be at least {MIN_SECRET_LENGTH} characters"
    );
    secret
}

/// POST /v1/check with raw image bytes: 200 as soon as the image is accepted,
/// classification happens in the background and never reaches the caller
async fn check(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let client = match authorize(&headers, &state.decoding_key) {
        Ok(client) => client,
        Err(reason) => return (StatusCode::UNAUTHORIZED, Json(json!({ "error": reason }))),
    };
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "empty body" })));
    }
    let Ok(permit) = Arc::clone(&state.limiter).try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "busy, retry later" })));
    };

    tracing::info!("api: {} byte(s) accepted from \"{client}\"", body.len());
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = process_submission(&state, body, &client).await {
            tracing::warn!("api submission from \"{client}\" failed: {e}");
        }
    });

    (StatusCode::OK, Json(json!({ "status": "accepted" })))
}

fn authorize(headers: &HeaderMap, key: &DecodingKey) -> Result<String, &'static str> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing Authorization header")?;
    let token = value.strip_prefix("Bearer ").ok_or("expected a Bearer token")?;

    let data = jsonwebtoken::decode::<Claims>(token, key, &Validation::new(Algorithm::HS256))
        .map_err(|_| "invalid or expired token")?;
    Ok(data.claims.sub)
}

async fn process_submission(
    state: &Arc<ApiState>,
    bytes: bytes::Bytes,
    client: &str,
) -> Result<(), Error> {
    // dino is the primary signal for api submissions, hashes corroborate
    let shadow_match = match &state.dino {
        Some(runtime) => dino_shadow::measure(Arc::clone(runtime), bytes.clone()).await?,
        None => None,
    };
    let verdict = detection::process_image(bytes.clone(), state.scam_db.snapshot()).await?;
    let hash_verdict = dino_shadow::verdict_tag(&verdict);

    let dino_hit = shadow_match.as_ref().is_some_and(dino_shadow::exceeds_review_gate);
    let hash_hit = hash_verdict != "clean";
    let sha_hex = img_config::hex_encode(&images::sha256_hash(&bytes));
    let submission_id = &sha_hex[..8];

    let dino_note = shadow_match
        .as_ref()
        .map(|m| format!("dino \"{}\" at {:.4}", m.entry_name, m.similarity))
        .unwrap_or_else(|| "dino off".to_string());
    tracing::info!(
        "api submission {submission_id} from \"{client}\": {dino_note}, hash {hash_verdict} \
         -> {}",
        if dino_hit || hash_hit { "report" } else { "clean" }
    );
    if !dino_hit && !hash_hit {
        return Ok(());
    }

    // the observation row keeps the card's labeling buttons functional
    let observation_id = match &shadow_match {
        Some(shadow_match) => Some(
            state
                .db
                .insert_dino_observation(&DinoObservation {
                    guild_id: CONFIG.api.report_guild_id.to_string(),
                    channel_id: "api".to_string(),
                    message_id: submission_id.to_string(),
                    author_id: client.to_string(),
                    entry_name: shadow_match.entry_name.clone(),
                    similarity: shadow_match.similarity as f64,
                    best_negative_similarity: shadow_match
                        .negative
                        .as_ref()
                        .map(|(_, similarity)| *similarity as f64),
                    hash_verdict,
                })
                .await?,
        ),
        None => None,
    };

    let filename = format!("{submission_id}.{}", image_extension(&bytes));
    let mut card = CreateMessage::new()
        .embed(get_api_report_embed(client, shadow_match.as_ref(), hash_verdict, &filename))
        .add_file(CreateAttachment::bytes(bytes.to_vec(), filename.clone()));
    if let Some(observation_id) = observation_id {
        card = card.components(interactions::dino_label_buttons(observation_id));
    }

    ChannelId::new(CONFIG.api.report_channel_id)
        .send_message(&state.http, card)
        .await?;
    Ok(())
}

/// `attachment://` references need an image-looking name; the format comes
/// from the magic bytes, not from anything the client claims
fn image_extension(bytes: &[u8]) -> &'static str {
    image::guess_format(bytes)
        .ok()
        .and_then(|format| format.extensions_str().first().copied())
        .unwrap_or("png")
}

/// `anti-scam issue-token <client-name> [days]` — mint an HS256 access token
/// for the check endpoint; needs the same API_JWT_SECRET as the server
pub fn run_issue_token(args: &[String]) {
    let (name, days) = match args {
        [name] => (name.as_str(), DEFAULT_TOKEN_DAYS),
        [name, days] => match days.parse::<u64>() {
            Ok(days) if days > 0 => (name.as_str(), days),
            _ => {
                eprintln!("\"{days}\" is not a valid number of days");
                std::process::exit(2);
            }
        },
        _ => {
            eprintln!("usage: anti-scam issue-token <client-name> [days]");
            std::process::exit(2);
        }
    };

    match issue_token(name, days) {
        Ok(token) => {
            println!("{token}");
            eprintln!("token for \"{name}\", valid {days} day(s)");
        }
        Err(e) => {
            eprintln!("issue-token failed: {e}");
            std::process::exit(1);
        }
    }
}

fn issue_token(name: &str, days: u64) -> Result<String, Error> {
    let secret = std::env::var(SECRET_ENV)
        .map_err(|_| format!("set the {SECRET_ENV} env var (>= {MIN_SECRET_LENGTH} characters)"))?;
    if secret.len() < MIN_SECRET_LENGTH {
        return Err(format!("{SECRET_ENV} must be at least {MIN_SECRET_LENGTH} characters").into());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = Claims {
        sub: name.to_string(),
        iat: now,
        exp: now + days * SECONDS_PER_DAY,
    };

    Ok(jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers
    }

    fn signed_token(secret: &str, exp: u64) -> String {
        let claims = Claims { sub: "tester".to_string(), iat: 0, exp };
        jsonwebtoken::encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
            .unwrap()
    }

    fn far_future() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + SECONDS_PER_DAY
    }

    #[test]
    fn authorize_accepts_a_valid_token() {
        let key = DecodingKey::from_secret(SECRET.as_bytes());
        let headers = bearer_headers(&signed_token(SECRET, far_future()));

        assert_eq!(authorize(&headers, &key), Ok("tester".to_string()));
    }

    #[test]
    fn authorize_rejects_a_wrong_secret() {
        let key = DecodingKey::from_secret(SECRET.as_bytes());
        let headers = bearer_headers(&signed_token("another-secret-another-secret-xx", far_future()));

        assert!(authorize(&headers, &key).is_err());
    }

    #[test]
    fn authorize_rejects_an_expired_token() {
        let key = DecodingKey::from_secret(SECRET.as_bytes());
        let headers = bearer_headers(&signed_token(SECRET, 1));

        assert!(authorize(&headers, &key).is_err());
    }

    #[test]
    fn authorize_rejects_missing_and_malformed_headers() {
        let key = DecodingKey::from_secret(SECRET.as_bytes());

        assert!(authorize(&HeaderMap::new(), &key).is_err());

        let mut basic = HeaderMap::new();
        basic.insert(header::AUTHORIZATION, "Basic dXNlcjpwdw==".parse().unwrap());
        assert!(authorize(&basic, &key).is_err());
    }

    #[test]
    fn image_extension_detects_png_magic() {
        let png_magic = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

        assert_eq!(image_extension(&png_magic), "png");
    }
}
