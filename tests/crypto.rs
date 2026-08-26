//! AES-128-CBC, key generation and HKDF derivation.

use drm_primitives::crypto::{
    aes_128_cbc_decrypt, aes_128_cbc_encrypt, derive_key, generate_aes_key, generate_iv,
    AES_128_KEY_LEN, AES_BLOCK_SIZE,
};
use drm_primitives::Error;

/// NIST SP 800-38A, F.2.1/F.2.2 — CBC-AES128 encryption.
///
/// The vector's plaintext is an exact multiple of the block size, so PKCS#7
/// appends a whole extra block; the first 64 bytes must still match the vector
/// byte for byte. Without this the implementation could be self-consistently
/// wrong and every round-trip test would still pass.
#[test]
fn matches_the_nist_cbc_aes128_vector() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ))
    .unwrap();
    let expected = hex::decode(concat!(
        "7649abac8119b246cee98e9b12e9197d",
        "5086cb9b507219ee95db113a917678b2",
        "73bed6b8e3c1743b7116e69e22229516",
        "3ff1caa1681fac09120eca307586e1a7",
    ))
    .unwrap();

    let ciphertext = aes_128_cbc_encrypt(&key, &iv, &plaintext).unwrap();

    assert_eq!(&ciphertext[..64], &expected[..]);
    assert_eq!(ciphertext.len(), 80, "one full block of PKCS#7 padding");
    assert_eq!(
        aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap(),
        plaintext
    );
}

#[test]
fn round_trips_a_short_message() {
    let key = generate_aes_key().unwrap();
    let iv = generate_iv().unwrap();
    let plaintext = b"a short segment";

    let ciphertext = aes_128_cbc_encrypt(&key, &iv, plaintext).unwrap();
    assert_ne!(ciphertext, plaintext.to_vec());
    assert_eq!(
        aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap(),
        plaintext
    );
}

#[test]
fn round_trips_across_multiple_blocks() {
    let key = generate_aes_key().unwrap();
    let iv = generate_iv().unwrap();
    let plaintext = b"a message long enough to span several AES blocks end to end";

    let ciphertext = aes_128_cbc_encrypt(&key, &iv, plaintext).unwrap();
    assert_eq!(
        aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap(),
        plaintext
    );
}

#[test]
fn round_trips_ten_kilobytes() {
    let key = generate_aes_key().unwrap();
    let iv = generate_iv().unwrap();
    let plaintext: Vec<u8> = (0..10_240).map(|i| (i % 256) as u8).collect();

    let ciphertext = aes_128_cbc_encrypt(&key, &iv, &plaintext).unwrap();
    assert_ne!(ciphertext, plaintext);
    assert_eq!(
        aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap(),
        plaintext
    );
}

#[test]
fn round_trips_a_single_byte() {
    let key = generate_aes_key().unwrap();
    let iv = generate_iv().unwrap();

    let ciphertext = aes_128_cbc_encrypt(&key, &iv, b"X").unwrap();
    assert_eq!(ciphertext.len(), AES_BLOCK_SIZE);
    assert_eq!(aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap(), b"X");
}

#[test]
fn empty_plaintext_becomes_one_padding_block() {
    let key = generate_aes_key().unwrap();
    let iv = generate_iv().unwrap();

    let ciphertext = aes_128_cbc_encrypt(&key, &iv, b"").unwrap();
    assert_eq!(ciphertext.len(), AES_BLOCK_SIZE);
    assert!(aes_128_cbc_decrypt(&key, &iv, &ciphertext)
        .unwrap()
        .is_empty());
}

#[test]
fn an_exact_block_gains_a_whole_padding_block() {
    let key = generate_aes_key().unwrap();
    let iv = generate_iv().unwrap();

    let ciphertext = aes_128_cbc_encrypt(&key, &iv, b"0123456789abcdef").unwrap();
    assert_eq!(ciphertext.len(), 2 * AES_BLOCK_SIZE);
}

#[test]
fn different_keys_give_different_ciphertext() {
    let iv = generate_iv().unwrap();
    let plaintext = b"same bytes, different keys";

    let a = aes_128_cbc_encrypt(&generate_aes_key().unwrap(), &iv, plaintext).unwrap();
    let b = aes_128_cbc_encrypt(&generate_aes_key().unwrap(), &iv, plaintext).unwrap();

    assert_ne!(a, b);
}

#[test]
fn different_ivs_give_different_ciphertext() {
    let key = generate_aes_key().unwrap();
    let plaintext = b"same bytes, different IVs";

    let a = aes_128_cbc_encrypt(&key, &generate_iv().unwrap(), plaintext).unwrap();
    let b = aes_128_cbc_encrypt(&key, &generate_iv().unwrap(), plaintext).unwrap();

    assert_ne!(a, b);
}

/// A short key used to reach `GenericArray::from_slice`, which panics. The
/// public API must report it instead.
#[test]
fn a_wrong_length_key_is_an_error_not_a_panic() {
    let iv = generate_iv().unwrap();

    let error = aes_128_cbc_encrypt(&[0u8; 15], &iv, b"x").unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidLength {
            expected: 16,
            actual: 15,
            ..
        }
    ));

    let error = aes_128_cbc_encrypt(&[0u8; 32], &iv, b"x").unwrap_err();
    assert!(matches!(error, Error::InvalidLength { actual: 32, .. }));
}

#[test]
fn a_wrong_length_iv_is_an_error_not_a_panic() {
    let key = generate_aes_key().unwrap();

    let error = aes_128_cbc_decrypt(&key, &[0u8; 8], &[0u8; 16]).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidLength {
            what: "AES-CBC IV",
            actual: 8,
            ..
        }
    ));
}

#[test]
fn an_unaligned_ciphertext_is_rejected() {
    let key = generate_aes_key().unwrap();
    let iv = generate_iv().unwrap();

    assert!(matches!(
        aes_128_cbc_decrypt(&key, &iv, &[0u8; 17]).unwrap_err(),
        Error::UnalignedCiphertext(17)
    ));
    assert!(matches!(
        aes_128_cbc_decrypt(&key, &iv, &[]).unwrap_err(),
        Error::UnalignedCiphertext(0)
    ));
}

/// The important half of unpadding: a wrong key must fail loudly rather than
/// truncating the plaintext by whatever the last byte happened to be.
#[test]
fn decrypting_with_the_wrong_key_reports_invalid_padding() {
    let iv = generate_iv().unwrap();
    let ciphertext = aes_128_cbc_encrypt(&generate_aes_key().unwrap(), &iv, b"payload").unwrap();

    let mut failures = 0;
    for _ in 0..16 {
        if let Err(error) = aes_128_cbc_decrypt(&generate_aes_key().unwrap(), &iv, &ciphertext) {
            assert!(matches!(error, Error::InvalidPadding));
            failures += 1;
        }
    }

    // A random wrong key produces valid-looking padding roughly 1 time in 256,
    // so over 16 attempts at least one rejection is all but certain.
    assert!(failures > 0, "no wrong key was rejected");
}

#[test]
fn derivation_is_deterministic() {
    let a = derive_key(b"master key material", b"asset-1").unwrap();
    let b = derive_key(b"master key material", b"asset-1").unwrap();

    assert_eq!(a, b);
    assert_eq!(a.len(), AES_128_KEY_LEN);
}

#[test]
fn different_key_ids_derive_different_keys() {
    let a = derive_key(b"master key material", b"asset-1").unwrap();
    let b = derive_key(b"master key material", b"asset-2").unwrap();

    assert_ne!(a, b);
}

#[test]
fn different_master_keys_derive_different_keys() {
    let a = derive_key(b"master key one", b"asset-1").unwrap();
    let b = derive_key(b"master key two", b"asset-1").unwrap();

    assert_ne!(a, b);
}

/// The XOR derivation this replaced returned `master ^ key_id`, so a
/// single-byte pair had a predictable first byte. HKDF must not.
#[test]
fn derivation_is_not_a_transparent_mix_of_its_inputs() {
    let derived = derive_key(b"A", b"B").unwrap();
    assert_ne!(derived[0], b'A' ^ b'B');
}

#[test]
fn an_empty_key_id_is_allowed() {
    let derived = derive_key(b"master key material", b"").unwrap();
    assert_eq!(derived.len(), AES_128_KEY_LEN);
    assert_ne!(derived, derive_key(b"master key material", b"x").unwrap());
}

/// The XOR derivation this replaced divided by `master_key.len()`.
#[test]
fn an_empty_master_key_is_an_error_not_a_panic() {
    assert!(matches!(
        derive_key(b"", b"asset-1").unwrap_err(),
        Error::EmptyInput("master key")
    ));
}

#[test]
fn a_derived_key_is_usable_as_a_content_key() {
    let content_key = derive_key(b"master key material", b"asset-1").unwrap();
    let iv = generate_iv().unwrap();

    let ciphertext = aes_128_cbc_encrypt(&content_key, &iv, b"a segment").unwrap();
    let recovered = derive_key(b"master key material", b"asset-1").unwrap();

    assert_eq!(
        aes_128_cbc_decrypt(&recovered, &iv, &ciphertext).unwrap(),
        b"a segment"
    );
}

#[test]
fn generated_keys_and_ivs_are_the_right_size_and_not_repeated() {
    let (key_a, key_b) = (generate_aes_key().unwrap(), generate_aes_key().unwrap());
    let (iv_a, iv_b) = (generate_iv().unwrap(), generate_iv().unwrap());

    assert_eq!(key_a.len(), AES_128_KEY_LEN);
    assert_eq!(iv_a.len(), AES_BLOCK_SIZE);
    assert_ne!(key_a, key_b);
    assert_ne!(iv_a, iv_b);
}
