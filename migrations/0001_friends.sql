CREATE TABLE friends (
    user REFERENCES users NOT NULL,
    target REFERENCES users NOT NULL,
    establish_time DATETIME NOT NULL
);

CREATE TABLE guilds (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(80) UNIQUE NOT NULL,
    create_time DATETIME NOT NULL
);

CREATE TABLE guild_members (
    guild REFERENCES guilds NOT NULL,
    user REFERENCES users NOT NULL,
    join_time DATETIME NOT NULL
);
