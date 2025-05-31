SELECT load_extension('./target/release/libsqlite_hash', 'sqlite3_hash_init');

.bail on
.header on
.mode box

.timer on

CREATE TABLE people (
    name TEXT,
    last_name TEXT
);

INSERT INTO people VALUES ('Alice', 'Smith'), ('Bob', 'Lee');

SELECT name, sha256(name) FROM people;
SELECT name, last_name, sha256(name, last_name) FROM people;

SELECT name, md5(name) FROM people;
SELECT name, last_name, md5(name, last_name) FROM people;

SELECT name, last_name, sha256(name, last_name), hex(sha256_bytes(name, last_name)) FROM people;
SELECT name, last_name, md5(name, last_name), hex(md5_bytes(name, last_name)) FROM people;

SELECT *, sha256(p.name, p.last_name) FROM people p;

SELECT *, blake2s256(p.name, p.last_name) FROM people p;