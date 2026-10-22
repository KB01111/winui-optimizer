//! Hashing and entropy helpers.
//!
//! All hashing is streamed in fixed-size chunks so memory use never depends on
//! file size, and an optional byte limit keeps work bounded for files that are
//! too large to hash.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

/// Chunk size used for streamed hashing and copying.
pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

/// Computes the SHA-256 of a file, streaming the contents in bounded chunks.
///
/// This function never loads the whole file into memory. It always hashes the
/// complete file; use [`hash_file_limited`] for a byte cap.
pub fn compute_sha256(path: &Path) -> io::Result<String> {
    match hash_file_limited(path, 0)? {
        Some((hash, _)) => Ok(hash),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hash byte limit exceeded",
        )),
    }
}

/// Hashes a file while reading at most `limit` bytes (`0` means no limit).
///
/// Returns `Ok(None)` as soon as the file is discovered to be larger than the
/// limit, without reading the rest of the file.
pub(crate) fn hash_file_limited(path: &Path, limit: u64) -> io::Result<Option<(String, u64)>> {
    let file = File::open(path)?;
    hash_reader_limited(BufReader::new(file), limit)
}

/// Hashes a reader while reading at most `limit` bytes (`0` means no limit).
pub(crate) fn hash_reader_limited<R: Read>(
    mut reader: R,
    limit: u64,
) -> io::Result<Option<(String, u64)>> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if limit > 0 && total > limit {
            return Ok(None);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Some((hex::encode(hasher.finalize()), total)))
}

/// SHA-256 of an in-memory buffer, lowercase hex.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Shannon entropy of `data` in bits per byte, in `[0.0, 8.0]`.
///
/// Empty input and single-value input yield `0.0`; a perfectly uniform byte
/// distribution approaches `8.0`.
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] = counts[byte as usize].saturating_add(1);
    }
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    if entropy.is_finite() {
        (entropy as f32).clamp(0.0, 8.0)
    } else {
        0.0
    }
}
