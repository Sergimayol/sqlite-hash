use hash::{hash_fn, ModeFormat, OutputFormat};

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

use paste::paste;

macro_rules! define_hash_functions {
    ($(($name:ident, $type:ty)),* $(,)?) => {
        paste! {
            $(
                fn [<$name _hex>](ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
                    hash_fn::<$type>(ctx, values, OutputFormat::Hex, ModeFormat::RawJoin)
                }

                fn [<$name _bytes>](ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
                    hash_fn::<$type>(ctx, values, OutputFormat::Bytes, ModeFormat::RawJoin)
                }

                fn [<$name _safe>](ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
                    hash_fn::<$type>(ctx, values, OutputFormat::Hex, ModeFormat::WithSep)
                }

                fn [<$name _bsafe>](ctx: *mut sqlite3_context, values: &[*mut sqlite3_value]) -> Result<()> {
                    hash_fn::<$type>(ctx, values, OutputFormat::Bytes, ModeFormat::WithSep)
                }
            )*
        }
    };
}

macro_rules! register_hash_functions {
    ($db:ident, $flags:expr, $( $name:ident ),* $(,)?) => {
        paste! {
            $(
                define_scalar_function($db, stringify!($name), -1, [<$name _hex>], $flags)?;
                define_scalar_function($db, concat!(stringify!($name), "_safe"), -1, [<$name _safe>], $flags)?;
                define_scalar_function($db, concat!(stringify!($name), "_bytes"), -1, [<$name _bytes>], $flags)?;
                define_scalar_function($db, concat!(stringify!($name), "_bsafe"), -1, [<$name _bsafe>], $flags)?;
            )*
        }
    };
}

define_hash_functions!(
    (md5, Md5),
    (sha1, Sha1),
    (sha224, Sha224),
    (sha256, Sha256),
    (sha384, Sha384),
    (sha512, Sha512),
    (sha512_224, Sha512_224),
    (sha512_256, Sha512_256),
    (sha3_224, Sha3_224),
    (sha3_256, Sha3_256),
    (sha3_384, Sha3_384),
    (sha3_512, Sha3_512),
    (ascon_hash, AsconHash256),
    (belt_hash, BeltHash),
    (blake2b512, Blake2b512),
    (blake2s256, Blake2s256),
    (fsb256, Fsb256),
    (gost94, Gost94CryptoPro),
    (groestl256, Groestl256),
    (jh256, Jh256),
    (md2, Md2),
    (md4, Md4),
    (ripemd160, Ripemd160),
    (shabal256, Shabal256),
    (skein256, Skein256),
    (sm3, Sm3),
    (streebog256, Streebog256),
    (tiger, Tiger),
    (whirlpool, Whirlpool),
);

#[sqlite_entrypoint]
pub fn sqlite3_hash_init(db: *mut sqlite3) -> Result<()> {
    let flags = FunctionFlags::UTF8 | FunctionFlags::DETERMINISTIC;

    register_hash_functions!(
        db,
        flags,
        md5,
        sha1,
        sha224,
        sha256,
        sha384,
        sha512,
        sha512_224,
        sha512_256,
        sha3_224,
        sha3_256,
        sha3_384,
        sha3_512,
        ascon_hash,
        belt_hash,
        blake2b512,
        blake2s256,
        fsb256,
        gost94,
        groestl256,
        jh256,
        md2,
        md4,
        ripemd160,
        shabal256,
        skein256,
        sm3,
        streebog256,
        tiger,
        whirlpool,
    );

    Ok(())
}
