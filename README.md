# SQLite3 Hash Extension

This SQLite3 extension provides most of the hash functions of the [RustCrypto/hashes](https://github.com/RustCrypto/hashes) lib as SQLite3 Scalar Functions.

## Includes

| Algorithm        | Text (hex)    | Binary (blob)       | Safe (hex with separator) | Safe (blob with separator) |
| ---------------- | ------------- | ------------------- | ------------------------- | -------------------------- |
| MD2              | `md2`         | `md2_bytes`         | `md2_safe`                | `md2_bsafe`                |
| MD4              | `md4`         | `md4_bytes`         | `md4_safe`                | `md4_bsafe`                |
| MD5              | `md5`         | `md5_bytes`         | `md5_safe`                | `md5_bsafe`                |
| SHA-1            | `sha1`        | `sha1_bytes`        | `sha1_safe`               | `sha1_bsafe`               |
| SHA2-224         | `sha224`      | `sha224_bytes`      | `sha224_safe`             | `sha224_bsafe`             |
| SHA2-256         | `sha256`      | `sha256_bytes`      | `sha256_safe`             | `sha256_bsafe`             |
| SHA2-384         | `sha384`      | `sha384_bytes`      | `sha384_safe`             | `sha384_bsafe`             |
| SHA2-512         | `sha512`      | `sha512_bytes`      | `sha512_safe`             | `sha512_bsafe`             |
| SHA2-512/224     | `sha512_224`  | `sha512_224_bytes`  | `sha512_224_safe`         | `sha512_224_bsafe`         |
| SHA2-512/256     | `sha512_256`  | `sha512_256_bytes`  | `sha512_256_safe`         | `sha512_256_bsafe`         |
| SHA3-224         | `sha3_224`    | `sha3_224_bytes`    | `sha3_224_safe`           | `sha3_224_bsafe`           |
| SHA3-256         | `sha3_256`    | `sha3_256_bytes`    | `sha3_256_safe`           | `sha3_256_bsafe`           |
| SHA3-384         | `sha3_384`    | `sha3_384_bytes`    | `sha3_384_safe`           | `sha3_384_bsafe`           |
| SHA3-512         | `sha3_512`    | `sha3_512_bytes`    | `sha3_512_safe`           | `sha3_512_bsafe`           |
| ASCON-256        | `ascon_hash`  | `ascon_hash_bytes`  | `ascon_hash_safe`         | `ascon_hash_bsafe`         |
| BELT             | `belt_hash`   | `belt_hash_bytes`   | `belt_hash_safe`          | `belt_hash_bsafe`          |
| BLAKE2b-512      | `blake2b512`  | `blake2b512_bytes`  | `blake2b512_safe`         | `blake2b512_bsafe`         |
| BLAKE2s-256      | `blake2s256`  | `blake2s256_bytes`  | `blake2s256_safe`         | `blake2s256_bsafe`         |
| FSB-256          | `fsb256`      | `fsb256_bytes`      | `fsb256_safe`             | `fsb256_bsafe`             |
| GOST94-CryptoPro | `gost94`      | `gost94_bytes`      | `gost94_safe`             | `gost94_bsafe`             |
| Groestl-256      | `groestl256`  | `groestl256_bytes`  | `groestl256_safe`         | `groestl256_bsafe`         |
| JH-256           | `jh256`       | `jh256_bytes`       | `jh256_safe`              | `jh256_bsafe`              |
| RIPEMD-160       | `ripemd160`   | `ripemd160_bytes`   | `ripemd160_safe`          | `ripemd160_bsafe`          |
| Shabal-256       | `shabal256`   | `shabal256_bytes`   | `shabal256_safe`          | `shabal256_bsafe`          |
| Skein-256        | `skein256`    | `skein256_bytes`    | `skein256_safe`           | `skein256_bsafe`           |
| SM3              | `sm3`         | `sm3_bytes`         | `sm3_safe`                | `sm3_bsafe`                |
| Streebog-256     | `streebog256` | `streebog256_bytes` | `streebog256_safe`        | `streebog256_bsafe`        |
| Tiger            | `tiger`       | `tiger_bytes`       | `tiger_safe`              | `tiger_bsafe`              |
| Whirlpool        | `whirlpool`   | `whirlpool_bytes`   | `whirlpool_safe`          | `whirlpool_bsafe`          |

---

## Description

- Functions **without suffix** (`sha256`, `md5`, etc.) return the hash as a **hexadecimal text string**, computed by simply concatenating all arguments (no separator).
- Functions with the suffix `_bytes` return the hash as a **binary blob**, also using simple concatenation with no separator.
- Functions with the suffix `_safe` return the hash as a **hexadecimal text string**, concatenating arguments with a special ASCII Unit Separator (`\x1f`) to avoid ambiguous concatenation collisions.
- Functions with the suffix `_bsafe` return the hash as a **binary blob**, concatenating arguments with the safe separator.

---

## Example usage in SQLite:

```sql
-- Simple concatenation, hex output
SELECT sha256('foo', 'bar');

-- Simple concatenation, binary blob output
SELECT sha256_bytes('foo', 'bar');

-- Safe concatenation with separator, hex output
SELECT sha256_safe('foo', 'bar');

-- Safe concatenation with separator, binary blob output
SELECT sha256_bsafe('foo', 'bar');
```
