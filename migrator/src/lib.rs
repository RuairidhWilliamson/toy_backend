#![warn(clippy::unwrap_used)]

use std::{
    ffi::OsStr,
    hash::Hasher,
    path::{Path, PathBuf},
};

use anyhow::Context;
use rustc_stable_hash::{FromStableHash, SipHasher128Hash};
use sqlx::Connection as _;

pub struct Migrator {
    pub migrations_directory: PathBuf,
    pub migrations: Vec<Migration>,
}

impl Migrator {
    pub fn new_from_env() -> anyhow::Result<Self> {
        let migrations_path = std::env::var("MIGRATIONS_DIR").context("MIGRATIONS_DIR not set")?;
        let migrations_directory = PathBuf::from(migrations_path);
        let migrations = migrations_from_directory(&migrations_directory)?;
        Ok(Self {
            migrations_directory,
            migrations,
        })
    }

    async fn create_migration_table(
        &self,
        conn: &mut sqlx::SqliteConnection,
    ) -> anyhow::Result<()> {
        sqlx::query("CREATE TABLE IF NOT EXISTS migrations (id BIGINT PRIMARY KEY NOT NULL, name VARCHAR(255) NOT NULL, hash BLOB NOT NULL)").execute(conn).await?;
        Ok(())
    }

    async fn perform_migrations(&self, conn: &mut sqlx::SqliteConnection) -> anyhow::Result<()> {
        let (max_applied_id,): (Option<i64>,) = sqlx::query_as("SELECT MAX(id) FROM migrations")
            .fetch_one(&mut *conn)
            .await?;
        for m in &self.migrations {
            m.perform(conn, max_applied_id)
                .await
                .with_context(|| format!("apply migration {}_{}", m.id, &m.name))?;
        }
        Ok(())
    }

    pub async fn run(&self, conn: &mut sqlx::SqliteConnection) -> anyhow::Result<()> {
        self.create_migration_table(conn).await?;
        self.perform_migrations(conn).await?;
        Ok(())
    }
}

fn migrations_from_directory(dir: &Path) -> anyhow::Result<Vec<Migration>> {
    let mut migrations = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let path = e.path();
        if path.extension() != Some(OsStr::new("sql")) {
            continue;
        }
        let file_name = path
            .file_stem()
            .context("get file stem failed")?
            .to_str()
            .context("non-utf8 migration name")?;
        let (id, name) = file_name
            .split_once('_')
            .context("invalid migration name, must include underscore")?;
        let id = id.parse()?;
        let name = name.to_owned();
        let sql = std::fs::read_to_string(path)?;
        let mut hasher = rustc_stable_hash::StableSipHasher128::new();
        hasher.write(sql.as_bytes());
        let hash = hasher.finish();
        migrations.push(Migration {
            id,
            name,
            sql,
            hash,
        });
    }
    migrations.sort_by_key(|m| m.id);
    Ok(migrations)
}

pub struct Migration {
    pub id: i64,
    pub name: String,
    pub sql: String,
    pub hash: Hash128,
}

impl Migration {
    async fn perform(
        &self,
        conn: &mut sqlx::SqliteConnection,
        max_applied_id: Option<i64>,
    ) -> anyhow::Result<()> {
        let apply_row: Option<(u64, Hash128)> =
            sqlx::query_as("SELECT id, hash FROM migrations WHERE id=?")
                .bind(self.id)
                .fetch_optional(&mut *conn)
                .await?;
        if let Some((_applied_id, applied_hash)) = apply_row {
            if applied_hash != self.hash {
                return Err(anyhow::anyhow!("applied hash does not match expected hash")
                    .context("migration has been modified after applying"));
            }
            return Ok(());
        }
        if let Some(max) = max_applied_id {
            if max > self.id {
                return Err(anyhow::anyhow!(
                    "max applied id {max} is greater than {} but {} has not been applied",
                    self.id,
                    self.id
                ));
            }
        }

        let mut tx = conn.begin().await?;
        sqlx::raw_sql(&self.sql).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO migrations (id, name, hash) VALUES (?, ?, ?)")
            .bind(self.id)
            .bind(&self.name)
            .bind(&self.hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[derive(PartialEq, Eq, sqlx::Type)]
#[sqlx(transparent)]
pub struct Hash128(Vec<u8>);

impl FromStableHash for Hash128 {
    type Hash = SipHasher128Hash;

    fn from(SipHasher128Hash(hash): SipHasher128Hash) -> Self {
        let bytes = hash.map(|x| x.to_le_bytes()).concat();
        Self(bytes)
    }
}
