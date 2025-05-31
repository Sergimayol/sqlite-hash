use hash::{hash_fn, OutputFormat};

use ascon_hash::AsconHash256;
use belt_hash::BeltHash;
use blake2::{Blake2b512, Blake2s256};
use fsb::Fsb256;
use gost94::Gost94CryptoPro;
use groestl::Groestl256;
use jh::Jh256;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use shabal::Shabal256;
use skein::Skein256;
use sm3::Sm3;
use streebog::Streebog256;
use tiger::Tiger;
use whirlpool::Whirlpool;

use sqlite_loadable::prelude::*;
use sqlite_loadable::{define_scalar_function, Result};

mod hash;

// === WRAPPERS ===
// Ascon
fn ascon_hash_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<AsconHash256>(ctx, values, OutputFormat::Hex)
}
fn ascon_hash_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<AsconHash256>(ctx, values, OutputFormat::Bytes)
}

// BelT
fn belt_hash_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<BeltHash>(ctx, values, OutputFormat::Hex)
}
fn belt_hash_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<BeltHash>(ctx, values, OutputFormat::Bytes)
}

// BLAKE2
fn blake2b512_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Blake2b512>(ctx, values, OutputFormat::Hex)
}
fn blake2b512_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Blake2b512>(ctx, values, OutputFormat::Bytes)
}
fn blake2s256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Blake2s256>(ctx, values, OutputFormat::Hex)
}
fn blake2s256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Blake2s256>(ctx, values, OutputFormat::Bytes)
}

// FSB
fn fsb256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Fsb256>(ctx, values, OutputFormat::Hex)
}
fn fsb256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Fsb256>(ctx, values, OutputFormat::Bytes)
}

// GOST94
fn gost94_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Gost94CryptoPro>(ctx, values, OutputFormat::Hex)
}
fn gost94_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Gost94CryptoPro>(ctx, values, OutputFormat::Bytes)
}

// Groestl
fn groestl256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Groestl256>(ctx, values, OutputFormat::Hex)
}
fn groestl256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Groestl256>(ctx, values, OutputFormat::Bytes)
}

// JH
fn jh256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Jh256>(ctx, values, OutputFormat::Hex)
}
fn jh256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Jh256>(ctx, values, OutputFormat::Bytes)
}

// RIPEMD
fn ripemd160_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Ripemd160>(ctx, values, OutputFormat::Hex)
}
fn ripemd160_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Ripemd160>(ctx, values, OutputFormat::Bytes)
}

// SHABAL
fn shabal256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Shabal256>(ctx, values, OutputFormat::Hex)
}
fn shabal256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Shabal256>(ctx, values, OutputFormat::Bytes)
}

// Skein
fn skein256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Skein256>(ctx, values, OutputFormat::Hex)
}
fn skein256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Skein256>(ctx, values, OutputFormat::Bytes)
}

// SM3
fn sm3_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sm3>(ctx, values, OutputFormat::Hex)
}
fn sm3_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sm3>(ctx, values, OutputFormat::Bytes)
}

// Streebog
fn streebog256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Streebog256>(ctx, values, OutputFormat::Hex)
}
fn streebog256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Streebog256>(ctx, values, OutputFormat::Bytes)
}

// Tiger
fn tiger_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Tiger>(ctx, values, OutputFormat::Hex)
}
fn tiger_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Tiger>(ctx, values, OutputFormat::Bytes)
}

// Whirlpool
fn whirlpool_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Whirlpool>(ctx, values, OutputFormat::Hex)
}
fn whirlpool_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Whirlpool>(ctx, values, OutputFormat::Bytes)
}

// MD2
fn md2_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md2>(ctx, values, OutputFormat::Hex)
}
fn md2_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md2>(ctx, values, OutputFormat::Bytes)
}

// MD4
fn md4_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md4>(ctx, values, OutputFormat::Hex)
}
fn md4_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md4>(ctx, values, OutputFormat::Bytes)
}

// MD5
fn md5_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md5>(ctx, values, OutputFormat::Hex)
}
fn md5_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Md5>(ctx, values, OutputFormat::Bytes)
}

// SHA-1
fn sha1_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha1>(ctx, values, OutputFormat::Hex)
}
fn sha1_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha1>(ctx, values, OutputFormat::Bytes)
}

// SHA-2
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

// SHA-3
fn sha3_224_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha3_224>(ctx, values, OutputFormat::Hex)
}
fn sha3_224_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha3_224>(ctx, values, OutputFormat::Bytes)
}

fn sha3_256_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha3_256>(ctx, values, OutputFormat::Hex)
}
fn sha3_256_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha3_256>(ctx, values, OutputFormat::Bytes)
}

fn sha3_384_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha3_384>(ctx, values, OutputFormat::Hex)
}
fn sha3_384_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha3_384>(ctx, values, OutputFormat::Bytes)
}

fn sha3_512_hex(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha3_512>(ctx, values, OutputFormat::Hex)
}
fn sha3_512_bytes(ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
    hash_fn::<Sha3_512>(ctx, values, OutputFormat::Bytes)
}

#[sqlite_entrypoint]
pub fn sqlite3_hash_init(db: *mut sqlite3) -> Result<()> {
    let flags = FunctionFlags::UTF8 | FunctionFlags::DETERMINISTIC;

    define_scalar_function(db, "ascon_hash", -1, ascon_hash_hex, flags)?;
    define_scalar_function(db, "ascon_hash_bytes", -1, ascon_hash_bytes, flags)?;

    define_scalar_function(db, "belt_hash", -1, belt_hash_hex, flags)?;
    define_scalar_function(db, "belt_hash_bytes", -1, belt_hash_bytes, flags)?;

    define_scalar_function(db, "blake2b512", -1, blake2b512_hex, flags)?;
    define_scalar_function(db, "blake2b512_bytes", -1, blake2b512_bytes, flags)?;
    define_scalar_function(db, "blake2s256", -1, blake2s256_hex, flags)?;
    define_scalar_function(db, "blake2s256_bytes", -1, blake2s256_bytes, flags)?;

    define_scalar_function(db, "fsb256", -1, fsb256_hex, flags)?;
    define_scalar_function(db, "fsb256_bytes", -1, fsb256_bytes, flags)?;

    define_scalar_function(db, "gost94", -1, gost94_hex, flags)?;
    define_scalar_function(db, "gost94_bytes", -1, gost94_bytes, flags)?;

    define_scalar_function(db, "groestl256", -1, groestl256_hex, flags)?;
    define_scalar_function(db, "groestl256_bytes", -1, groestl256_bytes, flags)?;

    define_scalar_function(db, "jh256", -1, jh256_hex, flags)?;
    define_scalar_function(db, "jh256_bytes", -1, jh256_bytes, flags)?;

    define_scalar_function(db, "ripemd160", -1, ripemd160_hex, flags)?;
    define_scalar_function(db, "ripemd160_bytes", -1, ripemd160_bytes, flags)?;

    define_scalar_function(db, "shabal256", -1, shabal256_hex, flags)?;
    define_scalar_function(db, "shabal256_bytes", -1, shabal256_bytes, flags)?;

    define_scalar_function(db, "skein256", -1, skein256_hex, flags)?;
    define_scalar_function(db, "skein256_bytes", -1, skein256_bytes, flags)?;

    define_scalar_function(db, "sm3", -1, sm3_hex, flags)?;
    define_scalar_function(db, "sm3_bytes", -1, sm3_bytes, flags)?;

    define_scalar_function(db, "streebog256", -1, streebog256_hex, flags)?;
    define_scalar_function(db, "streebog256_bytes", -1, streebog256_bytes, flags)?;

    define_scalar_function(db, "tiger", -1, tiger_hex, flags)?;
    define_scalar_function(db, "tiger_bytes", -1, tiger_bytes, flags)?;

    define_scalar_function(db, "whirlpool", -1, whirlpool_hex, flags)?;
    define_scalar_function(db, "whirlpool_bytes", -1, whirlpool_bytes, flags)?;

    define_scalar_function(db, "md2", -1, md2_hex, flags)?;
    define_scalar_function(db, "md2_bytes", -1, md2_bytes, flags)?;

    define_scalar_function(db, "md4", -1, md4_hex, flags)?;
    define_scalar_function(db, "md4_bytes", -1, md4_bytes, flags)?;

    define_scalar_function(db, "md5", -1, md5_hex, flags)?;
    define_scalar_function(db, "md5_bytes", -1, md5_bytes, flags)?;

    define_scalar_function(db, "sha1", -1, sha1_hex, flags)?;
    define_scalar_function(db, "sha1_bytes", -1, sha1_bytes, flags)?;

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

    define_scalar_function(db, "sha3_224", -1, sha3_224_hex, flags)?;
    define_scalar_function(db, "sha3_224_bytes", -1, sha3_224_bytes, flags)?;

    define_scalar_function(db, "sha3_256", -1, sha3_256_hex, flags)?;
    define_scalar_function(db, "sha3_256_bytes", -1, sha3_256_bytes, flags)?;

    define_scalar_function(db, "sha3_384", -1, sha3_384_hex, flags)?;
    define_scalar_function(db, "sha3_384_bytes", -1, sha3_384_bytes, flags)?;

    define_scalar_function(db, "sha3_512", -1, sha3_512_hex, flags)?;
    define_scalar_function(db, "sha3_512_bytes", -1, sha3_512_bytes, flags)?;

    Ok(())
}
