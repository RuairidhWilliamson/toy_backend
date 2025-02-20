#![allow(clippy::print_stderr, clippy::unwrap_used)]

use sqlx::{ConnectOptions as _, Connection as _, sqlite::SqliteConnectOptions};

#[tokio::main]
async fn main() {
    if let Err(err) = dotenvy::dotenv() {
        eprintln!(".env not found: {err}");
    }
    let migrator = migrator::Migrator::new_from_env().unwrap();
    let db_url = std::env::var("DATABASE_URL").unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        migrator.migrations_directory.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        db_url.strip_prefix("sqlite://").unwrap()
    );
    let options = SqliteConnectOptions::from_url(&db_url.parse().unwrap())
        .unwrap()
        .create_if_missing(true);
    let mut conn = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    migrator.run(&mut conn).await.unwrap();
}
