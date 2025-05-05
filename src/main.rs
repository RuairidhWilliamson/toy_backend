mod no_cache;
mod pages;
mod secrets;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{borrow::Cow, net::SocketAddr};

use anyhow::Context as _;
use api::string::SecretString;
use argon2::{
    Argon2, Params, PasswordHash, PasswordHasher as _, PasswordVerifier as _, Version,
    password_hash::SaltString,
};
use axum::{
    BoxError, Json, Router, async_trait,
    extract::{FromRequestParts, Host, State},
    handler::HandlerWithoutStateExt as _,
    http::{StatusCode, Uri, header::AUTHORIZATION, request::Parts, uri::Authority},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use chrono::Days;
use rand::RngCore as _;
use secrecy::{ExposeSecret as _, zeroize::Zeroizing};
use sqlx::{
    ConnectOptions as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    types::chrono::Utc,
};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dotenv_result = dotenvy::dotenv();
    tracing_subscriber::fmt::init();
    if let Err(err) = dotenv_result {
        tracing::warn!(".env does not exist: {err}");
    }

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

    let secrets = secrets::Secrets::load().context("load secrets")?;

    let templates_dir = get_env_var("TEMPLATES_DIR")?;
    let templates = tera::Tera::new(&format!("{templates_dir}/**/*"))?;

    let state = Arc::new(InternalAppState {
        secrets,
        db: pool,
        templates,
    });

    let app = Router::new()
        .nest("/", pages::pages_router())
        .route("/api/users", post(create_user))
        .route("/api/login", post(login))
        .route("/api/me", get(me))
        .layer(no_cache::NoCacheLayer)
        .layer(TraceLayer::new_for_http().on_failure(()))
        .with_state(state);

    let http_addr: SocketAddr = if let Ok(http_addr) = std::env::var("HTTP_ADDR") {
        http_addr.parse()?
    } else {
        SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            get_env_var("PORT")?.parse()?,
        )
    };

    if cfg!(feature = "tls") {
        let http_tls_addr: SocketAddr = get_env_var("HTTP_TLS_ADDR")?.parse()?;
        tokio::spawn(http_redirect_server(http_tls_addr, http_addr));
        let tls_cert_path = get_env_var("TLS_CERT_PATH")?;
        let tls_key_path = get_env_var("TLS_KEY_PATH")?;
        let tls_config = RustlsConfig::from_pem_file(tls_cert_path, tls_key_path).await?;
        tracing::info!("listening on http://{http_addr} and https://{http_tls_addr}");
        let handle = axum_server::Handle::default();
        {
            let handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
        }
        axum_server::bind_rustls(http_tls_addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        tracing::warn!("TLS disabled, data sent is not encrypted");
        tracing::info!("listening on http://{http_addr}");
        let listener = tokio::net::TcpListener::bind(http_addr).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }
    Ok(())
}

fn get_env_var(key: &str) -> anyhow::Result<String> {
    std::env::var(key).with_context(|| format!("env var {key} not set"))
}

async fn http_redirect_server(
    http_tls_addr: SocketAddr,
    http_addr: SocketAddr,
) -> anyhow::Result<()> {
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
        match make_https(&host, uri, http_tls_addr.port()) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    axum::serve(listener, redirect.into_make_service()).await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("signal received, starting graceful shutdown");
}

type AppState = Arc<InternalAppState>;

struct InternalAppState {
    secrets: secrets::Secrets,
    templates: tera::Tera,
    db: SqlitePool,
}

impl InternalAppState {
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
    #[error("template error: {0}")]
    Template(#[from] tera::Error),
    #[error("other error: {0}")]
    Other(Cow<'static, str>),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{self:#}");
        (StatusCode::INTERNAL_SERVER_ERROR, Json("an error occurred")).into_response()
    }
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
    let name = payload.username.as_str();
    let create_time = Utc::now().naive_utc();
    let row = sqlx::query!(
        "INSERT INTO users (name, password_hash, create_time, deleted) VALUES (?, ?, ?, 0) RETURNING id",
        name,
        password_hash,
        create_time,
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
    let name = payload.username.as_str();
    let Some(user_row) = sqlx::query!("SELECT id, password_hash FROM users WHERE name=?", name)
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
    let create_time = Utc::now().naive_utc();
    let expire_time = create_time + Days::new(14);
    sqlx::query!(
        "INSERT INTO sessions (id, user, token, create_time, expire_time) VALUES (?, ?, ?, ?, ?)",
        id,
        user_id,
        exposed_session_token,
        create_time,
        expire_time,
    )
    .execute(&state.db)
    .await?;
    Ok(api::Session {
        id,
        token,
        expires_at: expire_time,
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
            "SELECT users.id as user_id, users.name, sessions.token, sessions.expire_time FROM sessions INNER JOIN users ON users.id = sessions.user WHERE sessions.id=?",
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
        if row.expire_time < Utc::now().naive_utc() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if row.token != token {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let username = match row.name.as_str().try_into() {
            Ok(username) => username,
            Err(err) => {
                tracing::error!("username too long: {err:#}");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        Ok(Self {
            session_id: id,
            user_id: row.user_id,
            username,
        })
    }
}

async fn me(auth_user: AuthenticatedUser) -> Result<Json<api::MyProfile>, AppError> {
    Ok(Json(api::MyProfile {
        session_id: auth_user.session_id,
        user_id: auth_user.user_id,
        username: auth_user.username,
    }))
}
