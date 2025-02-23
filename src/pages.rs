use std::{borrow::Cow, time::Duration};

use axum::{
    Router,
    extract::{Path, State},
    response::Html,
    routing::get,
};
use chrono::NaiveDateTime;

use crate::{AppError, AppState};

pub fn pages_router() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/users", get(list_users))
        .route("/user/:user_id", get(get_user).delete(delete_user))
}

async fn home(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let mut ctx = tera::Context::new();
    let info = sqlx::query!("SELECT COUNT(users.id) as user_count FROM users")
        .fetch_one(&state.db)
        .await?;
    ctx.insert("user_count", &info.user_count);
    Ok(Html(state.templates.render("index.html", &ctx)?))
}

async fn list_users(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    #[derive(Debug, serde::Serialize)]
    struct UserRow {
        id: i64,
        name: String,
        create_time: NaiveDateTime,
        deleted: bool,
        session_count: i64,
    }
    let users = sqlx::query_as!(UserRow, "SELECT users.id, users.name, users.create_time, users.deleted, COUNT(sessions.id) as session_count FROM users LEFT JOIN sessions ON users.id = sessions.user GROUP BY users.id")
        .fetch_all(&state.db)
        .await?;
    let mut ctx = tera::Context::new();
    ctx.insert("users", &users);
    Ok(Html(state.templates.render("users.html", &ctx)?))
}

async fn get_user(
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Html<String>, AppError> {
    #[derive(Debug, serde::Serialize)]
    struct UserRow {
        id: i64,
        name: String,
        create_time: NaiveDateTime,
        deleted: bool,
    }
    let user = sqlx::query_as!(
        UserRow,
        "SELECT users.id, users.name, users.create_time, users.deleted FROM users WHERE users.id=?",
        user_id
    )
    .fetch_one(&state.db)
    .await?;
    let mut ctx = tera::Context::new();
    ctx.insert("user", &user);
    Ok(Html(state.templates.render("user.html", &ctx)?))
}

async fn delete_user(
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Html<String>, AppError> {
    tokio::time::sleep(Duration::from_secs(1)).await;
    if sqlx::query!("UPDATE users SET deleted=1 WHERE id=?", user_id)
        .execute(&state.db)
        .await?
        .rows_affected()
        == 0
    {
        return Err(AppError::Other(Cow::Borrowed("no rows affected")));
    }
    Ok(Html(String::from("<button disabled>Deleted</button>")))
}
