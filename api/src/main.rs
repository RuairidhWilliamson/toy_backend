#![allow(clippy::print_stderr, clippy::unwrap_used)]

fn main() {
    gen_schema::<api::CreateUser>();
    gen_schema::<api::User>();
    gen_schema::<api::LoginRequest>();
    gen_schema::<api::LoginResponse>();
}

fn gen_schema<T: schemars::JsonSchema>() {
    let schema = schemars::schema_for!(T);
    let name = schema
        .schema
        .metadata
        .as_ref()
        .unwrap()
        .title
        .as_ref()
        .unwrap()
        .as_str();
    let schema_dir = std::path::Path::new("generated").join("schemas");
    let schema_path = schema_dir.join(format!("{name}.schema.json"));
    std::fs::create_dir_all(&schema_dir).unwrap();
    let file = std::fs::File::create(&schema_path).unwrap();
    serde_json::to_writer_pretty(file, &schema).unwrap();
    eprintln!("Wrote {}", schema_path.display());
}
