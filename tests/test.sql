SELECT load_extension('./target/release/libsqlite_hash', 'sqlite3_hash_init');

.bail on
.header on
.mode box

.timer on

CREATE TABLE personas (
    nombre TEXT,
    apellido TEXT
);

INSERT INTO personas VALUES ('Alice', 'Smith'), ('Bob', 'Lee');

SELECT nombre, sha256(nombre) FROM personas;
SELECT nombre, apellido, sha256(nombre, apellido) FROM personas;

SELECT nombre, md5(nombre) FROM personas;
SELECT nombre, apellido, md5(nombre, apellido) FROM personas;

SELECT nombre, apellido, sha256(nombre, apellido), hex(sha256_bytes(nombre, apellido)) FROM personas;
SELECT nombre, apellido, md5(nombre, apellido), hex(md5_bytes(nombre, apellido)) FROM personas;

SELECT *, sha256(p.nombre, p.apellido) FROM personas p;