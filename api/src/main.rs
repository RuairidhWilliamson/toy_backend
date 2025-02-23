#![allow(clippy::print_stderr)]

use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    gen_schema::<api::CreateUser>()?;
    gen_schema::<api::User>()?;
    gen_schema::<api::LoginRequest>()?;
    gen_schema::<api::LoginResponse>()?;
    Ok(())
}

fn gen_schema<T: schemars::JsonSchema>() -> anyhow::Result<()> {
    let schema = schemars::schema_for!(T);
    let name = schema
        .schema
        .metadata
        .as_ref()
        .context("no metadata")?
        .title
        .as_ref()
        .context("no title")?
        .as_str();
    let schema_dir = std::path::Path::new("generated").join("schemas");
    let schema_path = schema_dir.join(format!("{name}.schema.json"));
    std::fs::create_dir_all(&schema_dir)?;
    let file = std::fs::File::create(&schema_path)?;
    serde_json::to_writer_pretty(file, &schema)?;
    eprintln!("Wrote {}", schema_path.display());
    Ok(())
}
