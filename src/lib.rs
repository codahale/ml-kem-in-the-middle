use std::iter;

use rand::{CryptoRng, Rng};

/// The length of an ML-KEM-768 ciphertext, in bytes.
pub const CT_LEN: usize = 1088;

/// The length of a hidden ML-KEM-768 ciphertext, in bytes.
pub const HIDDEN_CT_LEN: usize = 256 * 4 * 4;

/// Given an ML-KEM-768 ciphertext `ct`, returns an encoded form of `ct` which is indistinguishable
/// from random noise and can be decoded back to `ct` with [`reveal`].
pub fn hide(mut rng: impl Rng + CryptoRng, ct: &[u8; CT_LEN]) -> [u8; HIDDEN_CT_LEN] {
    // Decode the ciphertext into field elements.
    let mut u = [[0; N]; K];
    let mut c = ct.chunks_exact(320);
    for (u, c) in u.iter_mut().zip(c.by_ref()) {
        *u = ring_decode_and_decompress10(c.try_into().expect("should be 320 bytes"));
    }
    let c = c.remainder().try_into().expect("should be 128 bytes");
    let v = ring_decode_and_decompress4(c);

    let mut out = [0u8; HIDDEN_CT_LEN];
    for (fe, out) in u.iter().chain(iter::once(&v)).flatten().zip(out.chunks_exact_mut(4)) {
        let x = ((Q as u32) * rng.gen_range(0..(u32::MAX / (Q as u32)))) + *fe as u32;
        out.copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// Given the output of [`hide`], returns the original ciphertext.
pub fn reveal(ct_h: &[u8; HIDDEN_CT_LEN]) -> [u8; CT_LEN] {
    // Decode the hidden ciphertext as a sequence of 16-bit unsigned little endian integers,
    // reducing each to field elements modulo Q.
    let mut u = [[0; N]; K];
    let mut v = [0; N];
    for (re, b) in u.iter_mut().chain(iter::once(&mut v)).flatten().zip(ct_h.chunks_exact(4)) {
        let x = u32::from_le_bytes(b.try_into().expect("should be 4 bytes"));
        *re = (x % Q as u32) as u16;
    }

    // Re-encode the field elements as packed 10-bit integers.
    let mut c = [0; 1088];
    {
        let mut c = c.chunks_exact_mut(320);
        for (c, f) in c.by_ref().zip(u.iter().copied()) {
            c.copy_from_slice(&ring_compress_and_encode10(f));
        }
        c.into_remainder().copy_from_slice(&ring_compress_and_encode4(v));
    }
    c
}

// ML-KEM global constants.
const Q: u16 = 3329;
const N: usize = 256;
const K: usize = 3;

/// FieldElement is an integer modulo q, an element of ℤ_q. It is always reduced.
type FieldElement = u16;

// RingElement is a polynomial, an element of R_q, represented as an array according to FIPS 203
// (DRAFT), Section 2.4.
type RingElement = [FieldElement; N];

/// Returns a 320-byte encoding of a ring element, compressing four coefficients per five bytes.
///
/// It implements Compress₁₀, according to FIPS 203 (DRAFT), Definition 4.5, followed by
/// ByteEncode₁₀, according to FIPS 203 (DRAFT), Algorithm 4.
fn ring_compress_and_encode10(f: RingElement) -> [u8; 320] {
    let mut b = [0; 320];
    for (f, b) in f.chunks_exact(4).zip(b.chunks_exact_mut(5)) {
        let mut x = 0u64;
        x |= compress(f[0], 10) as u64;
        x |= (compress(f[1], 10) as u64) << 10;
        x |= (compress(f[2], 10) as u64) << 20;
        x |= (compress(f[3], 10) as u64) << 30;
        b[0] = (x) as u8;
        b[1] = (x >> 8) as u8;
        b[2] = (x >> 16) as u8;
        b[3] = (x >> 24) as u8;
        b[4] = (x >> 32) as u8;
    }
    b
}

/// Decode a 320-byte encoding of a ring element where each ten bits are mapped to an equidistant
/// distribution.
///
/// It implements ByteDecode₁₀, according to FIPS 203 (DRAFT), Algorithm 5, followed by
/// Decompress₁₀, according to FIPS 203 (DRAFT), Definition 4.6.
fn ring_decode_and_decompress10(b: [u8; 320]) -> RingElement {
    let mut f = [0; N];
    for (f, b) in f.chunks_exact_mut(4).zip(b.chunks_exact(5)) {
        let x = (b[0] as u64)
            | (b[1] as u64) << 8
            | (b[2] as u64) << 16
            | (b[3] as u64) << 24
            | (b[4] as u64) << 32;
        f[0] = decompress((x & 0b11_1111_1111) as u16, 10);
        f[1] = decompress((x >> 10 & 0b11_1111_1111) as u16, 10);
        f[2] = decompress((x >> 20 & 0b11_1111_1111) as u16, 10);
        f[3] = decompress((x >> 30 & 0b11_1111_1111) as u16, 10);
    }
    f
}

/// Returns a 128-byte encoding of a ring elements, compressing two coefficients per byte.
///
/// It implements Compress₄, according to FIPS 203 (DRAFT), Definition 4.5, followed by ByteEncode₄,
/// according to FIPS 203 (DRAFT), Algorithm 4.
fn ring_compress_and_encode4(f: RingElement) -> [u8; 128] {
    let mut b = [0; 128];
    for (b, f) in b.iter_mut().zip(f.chunks_exact(2)) {
        *b = (compress(f[0], 4) | compress(f[1], 4) << 4) as u8;
    }
    b
}

/// Decodes a 128-byte encoding of a ring element where each four bits are mapped to an equidistant
/// distribution.
///
/// It implements ByteDecode₄, according to FIPS 203 (DRAFT), Algorithm 5, followed by Decompress₄,
/// according to FIPS 203 (DRAFT), Definition 4.6.
fn ring_decode_and_decompress4(b: [u8; 128]) -> RingElement {
    let mut f = [0; N];
    for (f, b) in f.chunks_exact_mut(2).zip(b) {
        f[0] = decompress((b & 0b1111) as u16, 4);
        f[1] = decompress((b >> 4) as u16, 4);
    }
    f
}

const BARRETT_MULTIPLIER: u64 = 5039; // 4¹² / q
const BARRETT_SHIFT: usize = 24; // log₂(4¹²)

// Maps a field element uniformly to the range 0 to 2ᵈ-1, according to FIPS 203 (DRAFT), Definition
// 4.5.
fn compress(x: FieldElement, d: u8) -> u16 {
    // We want to compute (x * 2ᵈ) / q, rounded to nearest integer, with 1/2
    // rounding up (see FIPS 203 (DRAFT), Section 2.3).

    // Barrett reduction produces a quotient and a remainder in the range [0, 2q),
    // such that dividend = quotient * q + remainder.
    let dividend = (x as u32) << d; // x * 2ᵈ
    let mut quotient =
        (((dividend as u64).wrapping_mul(BARRETT_MULTIPLIER)) >> BARRETT_SHIFT) as u32;
    let remainder = dividend.wrapping_sub(quotient.wrapping_mul(Q as u32));

    // Since the remainder is in the range [0, 2q), not [0, q), we need to
    // portion it into three spans for rounding.
    //
    //     [ 0,       q/2     ) -> round to 0
    //     [ q/2,     q + q/2 ) -> round to 1
    //     [ q + q/2, 2q      ) -> round to 2
    //
    // We can convert that to the following logic: add 1 if remainder > q/2,
    // then add 1 again if remainder > q + q/2.
    //
    // Note that if remainder > x, then ⌊x⌋ - remainder underflows, and the top
    // bit of the difference will be set.
    quotient = quotient.wrapping_add((Q as u32 / 2).wrapping_sub(remainder) >> 31 & 1);
    quotient += (Q as u32 + (Q as u32) / 2 - remainder) >> 31 & 1;

    // quotient might have overflowed at this point, so reduce it by masking.
    let mask = (1u32 << d) - 1;
    (quotient & mask) as u16
}

// Maps a number x between 0 and 2ᵈ-1 uniformly to the full range of field elements, according to
// FIPS 203 (DRAFT), Definition 4.6.
fn decompress(y: u16, d: u8) -> FieldElement {
    // We want to compute (y * q) / 2ᵈ, rounded to nearest integer, with 1/2
    // rounding up (see FIPS 203 (DRAFT), Section 2.3).

    let dividend = (y as u32).wrapping_mul(Q as u32);
    let mut quotient = dividend >> d; // (y * q) / 2ᵈ

    // The d'th least-significant bit of the dividend (the most significant bit
    // of the remainder) is 1 for the top half of the values that divide to the
    // same quotient, which are the ones that round up.
    quotient = quotient.wrapping_add((dividend >> (d - 1)) & 1);

    // quotient is at most (2¹¹-1) * q / 2¹¹ + 1 = 3328, so it didn't overflow.
    quotient as u16
}

#[cfg(test)]
mod tests {
    use ml_kem::{Decapsulate as _, Encapsulate as _, KemCore as _};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate(&mut rng);
        for _ in 0..1_000 {
            let (ct, ss) = ek.encapsulate(&mut rng).expect("should encapsulate");
            let ct_h = hide(&mut rng, &ct.into());
            let ct_p = reveal(&ct_h);
            let ss_p = dk.decapsulate(&ct_p.into()).expect("should decapsulate");
            assert_eq!(ss, ss_p);
        }
    }
}
