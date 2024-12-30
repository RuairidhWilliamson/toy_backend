#![warn(clippy::unwrap_used)]

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use anyhow::Context;
use rusqlite::{params, Connection, OptionalExtension};

pub struct Migrator {
    pub conn: Connection,
    pub db_path: PathBuf,
    pub migrations_directory: PathBuf,
    pub migrations: Vec<Migration>,
}

impl Migrator {
    pub fn new_from_env() -> anyhow::Result<Self> {
        let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL not set")?;
        let db_path = Path::new(
            db_url
                .strip_prefix("sqlite://")
                .context("DATABASE_URL must startwith 'sqlite://'")?,
        );
        let conn = Connection::open(db_path)?;
        let migrations_path = std::env::var("MIGRATIONS_DIR").context("MIGRATIONS_DIR not set")?;
        let migrations_directory = PathBuf::from(migrations_path);
        let migrations = migrations_from_directory(&migrations_directory)?;
        Ok(Self {
            conn,
            db_path: db_path.to_owned(),
            migrations_directory,
            migrations,
        })
    }

    fn create_migration_table(&mut self) -> anyhow::Result<()> {
        self.conn
            .execute("CREATE TABLE IF NOT EXISTS migrations (id BIGINT PRIMARY KEY NOT NULL, name VARCHAR(255) NOT NULL)", ())
            ?;
        Ok(())
    }

    fn perform_migrations(&mut self) -> anyhow::Result<()> {
        let max_applied_id: Option<u64> =
            self.conn
                .query_row("SELECT MAX(id) FROM migrations", (), |row| row.get(0))?;
        for m in &self.migrations {
            let id: Option<u64> = self
                .conn
                .query_row(
                    "SELECT id FROM migrations WHERE id=?1",
                    params![m.id],
                    |row| row.get(0),
                )
                .optional()?;
            let has_applied = id.is_some();
            if has_applied {
                continue;
            }
            if let Some(max) = max_applied_id {
                if max > m.id {
                    return Err(anyhow::anyhow!(
                        "max applied id {max} is greater than {} but {} has not been applied",
                        m.id,
                        m.id
                    ));
                }
            }
            let tx = self.conn.transaction()?;
            tx.execute_batch(&m.sql)
                .with_context(|| format!("failed to apply migration {}_{}", m.id, m.name))?;
            tx.execute(
                "INSERT INTO migrations (id, name) VALUES (?1, ?2)",
                params![m.id, &m.name],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        self.create_migration_table()?;
        self.perform_migrations()?;
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
        migrations.push(Migration { id, name, sql });
    }
    migrations.sort_by_key(|m| m.id);
    Ok(migrations)
}

pub struct Migration {
    pub id: u64,
    pub name: String,
    pub sql: String,
}
