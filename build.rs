#![allow(clippy::print_stderr, clippy::unwrap_used)]

fn main() {
    if let Err(err) = dotenvy::dotenv() {
        eprintln!(".env not found: {err}");
    }
    let mut migrator = migrator::Migrator::new_from_env().unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        migrator.migrations_directory.display()
    );
    println!("cargo:rerun-if-changed={}", migrator.db_path.display());
    migrator.run().unwrap();
}
