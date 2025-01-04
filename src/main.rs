mod secrets;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use api::string::SecretString;
use argon2::{
    password_hash::SaltString, Argon2, Params, PasswordHash, PasswordHasher as _,
    PasswordVerifier as _, Version,
};
use axum::{
    async_trait,
    extract::{FromRequestParts, Host, State},
    handler::HandlerWithoutStateExt as _,
    http::{header::AUTHORIZATION, request::Parts, uri::Authority, StatusCode, Uri},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    BoxError, Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{prelude::BASE64_STANDARD, Engine as _};
use chrono::Days;
use rand::RngCore as _;
use secrecy::{zeroize::Zeroizing, ExposeSecret as _};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    types::chrono::Utc,
    ConnectOptions as _, SqlitePool,
};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Err(err) = dotenvy::dotenv() {
        tracing::error!(".env does not exist: {err}");
    }
    tracing_subscriber::fmt::init();

    let db_url = get_env_var("DATABASE_URL")?;

    let options = SqliteConnectOptions::from_url(&db_url.parse()?)?
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new().connect_with(options).await?;

    migrator::Migrator::new_from_env()
        .context("prepare migrations")?
        .run(pool.acquire().await?.as_mut())
        .await
        .context("apply migrations")?;

    let secrets = Arc::new(secrets::Secrets::load().context("load secrets")?);
    let state = AppState { secrets, db: pool };

    let app = Router::new()
        .route("/", get(root))
        .route("/users", post(create_user))
        .route("/login", post(login))
        .route("/me", get(me))
        .layer(TraceLayer::new_for_http().on_failure(()))
        .with_state(state);

    let http_addr: SocketAddr = get_env_var("HTTP_ADDR")?.parse()?;

    if cfg!(feature = "tls") {
        let http_tls_addr: SocketAddr = get_env_var("HTTP_TLS_ADDR")?.parse()?;
        tokio::spawn(http_redirect_server(http_tls_addr, http_addr));
        let tls_cert_path = get_env_var("TLS_CERT_PATH")?;
        let tls_key_path = get_env_var("TLS_KEY_PATH")?;
        let tls_config = RustlsConfig::from_pem_file(tls_cert_path, tls_key_path).await?;
        tracing::info!("listening on http://{http_addr} and https://{http_tls_addr}");
        axum_server::bind_rustls(http_tls_addr, tls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        tracing::warn!("TLS disabled, data sent is not encrypted");
        tracing::info!("listening on http://{http_addr}");
        axum_server::bind(http_addr)
            .serve(app.into_make_service())
            .await?;
    }
    Ok(())
}

fn get_env_var(key: &str) -> anyhow::Result<String> {
    std::env::var(key).with_context(|| format!("env var {key} not set"))
}

async fn http_redirect_server(https: SocketAddr, http: SocketAddr) -> anyhow::Result<()> {
    fn make_https(host: &str, uri: Uri, https_port: u16) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse()?);
        }

        let authority: Authority = host.parse()?;
        let bare_host = match authority.port() {
            Some(_) => {
                let (host, _) = authority
                    .as_str()
                    .rsplit_once(':')
                    .context("split port structure")?;
                host
            }
            None => authority.as_str(),
        };

        parts.authority = Some(format!("{bare_host}:{https_port}").parse()?);

        Ok(Uri::from_parts(parts)?)
    }
    let redirect = move |Host(host): Host, uri: Uri| async move {
        match make_https(&host, uri, https.port()) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };
    axum_server::bind(http)
        .serve(redirect.into_make_service())
        .await?;
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
    let Some(user_row) = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE username=?",
        username,
    )
    .fetch_optional(&state.db)
    .await?
    else {
        return Ok(Json(api::LoginResponse::BadUsername));
    };
    if let Err(err) = state.password_hasher().verify_password(
        payload.password.expose_secret().as_bytes(),
        &PasswordHash::new(&user_row.password_hash)?,
    ) {
        tracing::info!("login failed verify password: {err}");
        Ok(Json(api::LoginResponse::BadPassword))
    } else {
        Ok(Json(api::LoginResponse::Success {
            session: create_session(user_row.id, state).await?,
        }))
    }
}

async fn create_session(user_id: api::UserId, state: AppState) -> Result<api::Session, AppError> {
    let id = uuid::Uuid::new_v4();
    let mut session_token_raw = Zeroizing::new([0u8; 64]);
    rand::rngs::OsRng.fill_bytes(session_token_raw.as_mut());
    let token = Zeroizing::new(BASE64_STANDARD.encode(&session_token_raw));
    let token = SecretString::new(&token);
    let exposed_session_token = token.expose_secret();
    let created_at = Utc::now().naive_utc();
    let expires_at = created_at + Days::new(14);
    sqlx::query!(
        "INSERT INTO sessions (id, user, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        id,
        user_id,
        exposed_session_token,
        created_at,
        expires_at,
    )
    .execute(&state.db)
    .await?;
    Ok(api::Session {
        id,
        token,
        expires_at,
    })
}

#[derive(Debug)]
pub struct AuthenticatedUser {
    session_id: api::SessionId,
    user_id: api::UserId,
    username: api::Username,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(auth) = parts.headers.get(AUTHORIZATION) else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        let Ok(auth) = auth.to_str() else {
            return Err(StatusCode::UNAUTHORIZED);
        };

        let Some((id, token)) = auth.split_once('.') else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        let id: api::SessionId = match id.parse() {
            Ok(id) => id,
            Err(err) => {
                tracing::error!("failed to parse session id: {err:?}");
                return Err(StatusCode::UNAUTHORIZED);
            }
        };
        let row = match sqlx::query!(
            "SELECT users.id as user_id, users.username, sessions.token, sessions.expires_at FROM sessions INNER JOIN users ON users.id = sessions.user WHERE sessions.id=?",
            id
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(row) => row,
            Err(err) => {
                tracing::error!("lookup session: {err:#}");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        let Some(row) = row else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        if row.token != token {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let username = match row.username.as_str().try_into() {
            Ok(username) => username,
            Err(err) => {
                tracing::error!("username too long: {err:#}");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        return Ok(Self {
            session_id: id,
            user_id: row.user_id,
            username,
        });
    }
}

async fn me(auth_user: AuthenticatedUser) -> Result<Json<api::MyProfile>, AppError> {
    Ok(Json(api::MyProfile {
        session_id: auth_user.session_id,
        user_id: auth_user.user_id,
        username: auth_user.username,
    }))
}
