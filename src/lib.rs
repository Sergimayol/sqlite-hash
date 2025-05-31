use hash::{hash_fn, OutputFormat};
use md5::Md5;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sqlite_loadable::prelude::*;
use sqlite_loadable::{define_scalar_function, Result};

mod hash;

// === Wrappers ===
// MD5
fn md5_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md5>(ctx, values, OutputFormat::Hex)
}
fn md5_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md5>(ctx, values, OutputFormat::Bytes)
}

// SHA224
fn sha224_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha224>(ctx, values, OutputFormat::Hex)
}
fn sha224_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha224>(ctx, values, OutputFormat::Bytes)
}

// SHA256
fn sha256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha256>(ctx, values, OutputFormat::Hex)
}
fn sha256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha256>(ctx, values, OutputFormat::Bytes)
}

// SHA384
fn sha384_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha384>(ctx, values, OutputFormat::Hex)
}
fn sha384_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha384>(ctx, values, OutputFormat::Bytes)
}

// SHA512
fn sha512_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha512>(ctx, values, OutputFormat::Hex)
}
fn sha512_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha512>(ctx, values, OutputFormat::Bytes)
}

// SHA512/224
fn sha512_224_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha512_224>(ctx, values, OutputFormat::Hex)
}
fn sha512_224_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha512_224>(ctx, values, OutputFormat::Bytes)
}

// SHA512/256
fn sha512_256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha512_256>(ctx, values, OutputFormat::Hex)
}
fn sha512_256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha512_256>(ctx, values, OutputFormat::Bytes)
}

#[sqlite_entrypoint]
pub fn sqlite3_hash_init(db: *mut sqlite3) -> Result<()> {
    let flags = FunctionFlags::UTF8 | FunctionFlags::DETERMINISTIC;

    // MD5
    define_scalar_function(db, "md5", -1, md5_hex, flags)?;
    define_scalar_function(db, "md5_bytes", -1, md5_bytes, flags)?;

    // SHA2
    define_scalar_function(db, "sha224", -1, sha224_hex, flags)?;
    define_scalar_function(db, "sha224_bytes", -1, sha224_bytes, flags)?;

    define_scalar_function(db, "sha256", -1, sha256_hex, flags)?;
    define_scalar_function(db, "sha256_bytes", -1, sha256_bytes, flags)?;

    define_scalar_function(db, "sha384", -1, sha384_hex, flags)?;
    define_scalar_function(db, "sha384_bytes", -1, sha384_bytes, flags)?;

    define_scalar_function(db, "sha512", -1, sha512_hex, flags)?;
    define_scalar_function(db, "sha512_bytes", -1, sha512_bytes, flags)?;

    define_scalar_function(db, "sha512_224", -1, sha512_224_hex, flags)?;
    define_scalar_function(db, "sha512_224_bytes", -1, sha512_224_bytes, flags)?;

    define_scalar_function(db, "sha512_256", -1, sha512_256_hex, flags)?;
    define_scalar_function(db, "sha512_256_bytes", -1, sha512_256_bytes, flags)?;

    Ok(())
}
