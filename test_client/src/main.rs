#![allow(clippy::unwrap_used, clippy::print_stderr)]

use std::time::Instant;

use rand::Rng as _;

#[expect(clippy::result_large_err)]
fn main() -> Result<(), ureq::Error> {
    let start = Instant::now();

    let addr = "http://127.0.0.1:3000";

    let suffix: u32 = rand::rngs::OsRng.gen();
    let username = format!("test_client_{suffix}");

    // Test root path
    let root_resp = ureq::get(addr).call()?;
    assert_eq!(root_resp.status(), 200);
    assert_eq!(root_resp.into_string()?, "Hello, World!");

    // Create user
    let user_resp = ureq::post(&format!("{addr}/users")).send_json(ureq::json!({
        "username": &username,
        "password": "123456789",
    }))?;
    assert_eq!(user_resp.status(), 200);
    let _user_body: ureq::serde_json::Value = user_resp.into_json()?;

    // Login
    let login_resp = ureq::post(&format!("{addr}/login")).send_json(ureq::json!({
        "username": &username,
        "password": "123456789",
    }))?;
    assert_eq!(login_resp.status(), 200);
    let login_body: ureq::serde_json::Value = login_resp.into_json()?;
    let session = login_body.get("Success").unwrap().get("session").unwrap();
    let session_id = session.get("id").unwrap().as_str().unwrap();
    let session_token = session.get("token").unwrap().as_str().unwrap();

    let me_resp = ureq::get(&format!("{addr}/me"))
        .set("Authorization", &format!("{session_id}.{session_token}"))
        .call()?;
    assert_eq!(me_resp.status(), 200);
    let me_resp: ureq::serde_json::Value = me_resp.into_json()?;
    assert_eq!(me_resp.get("username").unwrap(), &username);

    eprintln!("Success");
    eprintln!("Elapsed {:#?}", start.elapsed());

    Ok(())
}
