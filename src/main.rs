mod secrets;

use std::sync::Arc;

use anyhow::Context as _;
use argon2::{
    password_hash::SaltString, Argon2, Params, PasswordHash, PasswordHasher as _,
    PasswordVerifier as _, Version,
};
use axum::response::IntoResponse;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use secrecy::ExposeSecret as _;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Err(err) = dotenvy::dotenv() {
        tracing::error!(".env does not exist: {err}");
    }
    tracing_subscriber::fmt::init();

    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL not set")?;
    migrator::Migrator::new_from_env()?.run()?;

    let pool = SqlitePoolOptions::new().connect(&db_url).await?;

    let secrets = Arc::new(secrets::Secrets::load()?);
    let state = AppState { secrets, db: pool };

    let app = Router::new()
        .route("/", get(root))
        .route("/users", post(create_user))
        .route("/login", post(login))
        .layer(TraceLayer::new_for_http().on_failure(()))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    secrets: Arc<secrets::Secrets>,
    db: SqlitePool,
}

impl AppState {
    fn password_hasher(&self) -> Argon2<'_> {
        Argon2::new_with_secret(
            self.secrets.password_pepper.expose_secret().as_bytes(),
            argon2::Algorithm::Argon2id,
            Version::default(),
            Params::default(),
        )
        .expect("password pepper is too long")
    }
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("password hash error: {0}")]
    PasswordHash(#[from] argon2::password_hash::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{self:#}");
        (StatusCode::INTERNAL_SERVER_ERROR, Json("an error occurred")).into_response()
    }
}

async fn root() -> &'static str {
    "Hello, World!"
}

async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<api::CreateUser>,
) -> Result<Json<api::User>, AppError> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let password_hash = state
        .password_hasher()
        .hash_password(payload.password.expose_secret().as_bytes(), &salt)?
        .to_string();
    let username = payload.username.as_str();
    let row = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id",
        username,
        password_hash,
    )
    .fetch_one(&state.db)
    .await?;
    let user = api::User {
        id: row.id,
        username: payload.username,
    };
    Ok(Json(user))
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<api::LoginRequest>,
) -> Result<Json<api::LoginResponse>, AppError> {
    let username = payload.username.as_str();
    let row = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE username=?",
        username,
    )
    .fetch_one(&state.db)
    .await?;
    if let Err(err) = state.password_hasher().verify_password(
        payload.password.expose_secret().as_bytes(),
        &PasswordHash::new(&row.password_hash)?,
    ) {
        tracing::info!("login failed verify password: {err}");
        Ok(Json(api::LoginResponse::Failure))
    } else {
        Ok(Json(api::LoginResponse::Success))
    }
}
