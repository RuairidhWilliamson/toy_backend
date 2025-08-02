An example web app written in rust.

## Run

Run without or with TLS

```bash
cargo r
cargo r -F tls
```

Run test test client

```bash
cargo r -p test_client
```

## Docker

You can use docker to build and run the backend

```bash
docker build -t toy_backend .
touch db.sqlite3
docker container run \
  --name toy_backend \
  --rm \
  -it \
  -e DATABASE_URL=sqlite://db.sqlite3 \
  -e PORT=3000 \
  -p 0.0.0.0:3000:3000/tcp \
  --mount type=bind,source=./secrets.json,destination=/app/secrets.json,readonly \
  --mount type=bind,source=./db.sqlite3,destination=/app/db.sqlite3 \
  toy_backend
```

### Docker compose

You can also use docker compose to build and run the backend

```bash
touch db.sqlite3
docker compose up
```

## Checks

```bash
cargo fmt --check
cargo clippy --workspace
```
