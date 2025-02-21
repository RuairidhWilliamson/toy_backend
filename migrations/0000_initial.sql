-- Create users table
CREATE TABLE users (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    create_time DATETIME NOT NULL,
    deleted INTEGER NOT NULL
);

CREATE TABLE sessions (
    id BLOB NOT NULL,
    user REFERENCES users NOT NULL,
    token VARCHAR(255) NOT NULL,
    create_time DATETIME NOT NULL,
    expire_time DATETIME NOT NULL
);
