use hash::{hash_fn, OutputFormat};
use md5::Md5;
use sha2::Sha256;
use sqlite_loadable::prelude::*;
use sqlite_loadable::{define_scalar_function, Result};

mod hash;

fn sha256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha256>(ctx, values, OutputFormat::Hex)
}

fn sha256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha256>(ctx, values, OutputFormat::Bytes)
}

fn md5_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md5>(ctx, values, OutputFormat::Hex)
}

fn md5_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md5>(ctx, values, OutputFormat::Bytes)
}

#[sqlite_entrypoint]
pub fn sqlite3_hash_init(db: *mut sqlite3) -> Result<()> {
    let flags = FunctionFlags::UTF8 | FunctionFlags::DETERMINISTIC;

    define_scalar_function(db, "sha256", -1, sha256_hex, flags)?;
    define_scalar_function(db, "sha256_bytes", -1, sha256_bytes, flags)?;

    define_scalar_function(db, "md5", -1, md5_hex, flags)?;
    define_scalar_function(db, "md5_bytes", -1, md5_bytes, flags)?;

    Ok(())
}
