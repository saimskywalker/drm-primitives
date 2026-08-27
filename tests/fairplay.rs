//! FairPlay certificate handling, FPS init data, and `EXT-X-KEY` parsing.

use drm_primitives::fairplay::{FairPlayCertificate, FpsInitData, HlsKeyParser};
use drm_primitives::Error;

#[test]
fn parses_a_fairplay_key_tag() {
    let tag = concat!(
        r#"#EXT-X-KEY:METHOD=SAMPLE-AES,KEYFORMAT="com.apple.streamingkeydelivery","#,
        r#"KEYFORMATVERSIONS="1",URI="skd://asset-123","#,
        "IV=0x1234567890ABCDEF1234567890ABCDEF",
    );

    let info = HlsKeyParser::parse(tag).unwrap();

    assert_eq!(info.method, "SAMPLE-AES");
    assert_eq!(info.uri.as_deref(), Some("skd://asset-123"));
    assert_eq!(
        info.key_format.as_deref(),
        Some("com.apple.streamingkeydelivery")
    );
    assert_eq!(info.key_format_versions.as_deref(), Some("1"));
    assert_eq!(info.iv.as_ref().map(Vec::len), Some(16));
}

#[test]
fn parses_a_plain_aes_128_key_tag_without_an_iv() {
    let info =
        HlsKeyParser::parse(r#"#EXT-X-KEY:METHOD=AES-128,URI="https://example.com/key.key""#)
            .unwrap();

    assert_eq!(info.method, "AES-128");
    assert_eq!(info.uri.as_deref(), Some("https://example.com/key.key"));
    assert!(info.iv.is_none());
    assert!(info.key_format.is_none());
    assert!(info.key_format_versions.is_none());
}

/// `METHOD=NONE` is how a playlist declares that encryption stops, and it
/// carries no URI.
#[test]
fn parses_method_none() {
    let info = HlsKeyParser::parse("#EXT-X-KEY:METHOD=NONE").unwrap();

    assert_eq!(info.method, "NONE");
    assert!(info.uri.is_none());
}

/// The bug a naive `split(',')` has: a key URI with a query string can contain
/// a comma, and splitting on it truncates the URI into something that still
/// looks like it parsed.
#[test]
fn a_comma_inside_a_quoted_uri_does_not_split_the_attribute() {
    let tag = r#"#EXT-X-KEY:METHOD=AES-128,URI="https://keys.example/k?ids=1,2,3&t=9",KEYFORMAT="identity""#;

    let info = HlsKeyParser::parse(tag).unwrap();

    assert_eq!(
        info.uri.as_deref(),
        Some("https://keys.example/k?ids=1,2,3&t=9")
    );
    assert_eq!(info.key_format.as_deref(), Some("identity"));
}

#[test]
fn parses_a_session_key_tag() {
    let info =
        HlsKeyParser::parse(r#"#EXT-X-SESSION-KEY:METHOD=SAMPLE-AES,URI="skd://asset-1""#).unwrap();

    assert_eq!(info.method, "SAMPLE-AES");
    assert_eq!(info.uri.as_deref(), Some("skd://asset-1"));
}

#[test]
fn unknown_attributes_are_ignored() {
    let info = HlsKeyParser::parse(
        r#"#EXT-X-KEY:METHOD=AES-128,URI="https://example.com/k",X-VENDOR-THING="whatever""#,
    )
    .unwrap();

    assert_eq!(info.method, "AES-128");
}

#[test]
fn an_uppercase_hex_prefix_is_accepted() {
    let info = HlsKeyParser::parse(
        r#"#EXT-X-KEY:METHOD=AES-128,URI="https://e/k",IV=0X000102030405060708090A0B0C0D0E0F"#,
    )
    .unwrap();

    assert_eq!(info.iv.unwrap(), (0u8..16).collect::<Vec<u8>>());
}

#[test]
fn a_tag_without_a_method_is_rejected() {
    assert!(matches!(
        HlsKeyParser::parse(r#"#EXT-X-KEY:URI="https://example.com/key.key""#).unwrap_err(),
        Error::Malformed { .. }
    ));
}

#[test]
fn a_line_that_is_not_a_key_tag_is_rejected() {
    assert!(matches!(
        HlsKeyParser::parse("#EXT-X-TARGETDURATION:6").unwrap_err(),
        Error::Malformed { .. }
    ));
}

#[test]
fn an_iv_that_is_not_hex_is_rejected() {
    assert!(matches!(
        HlsKeyParser::parse(r#"#EXT-X-KEY:METHOD=AES-128,URI="https://e/k",IV=0xZZZZ"#)
            .unwrap_err(),
        Error::Hex(_)
    ));
}

/// A short IV is the kind of thing a hand-written packager emits, and a player
/// given one silently pads it. Rejecting is more useful than guessing.
#[test]
fn an_iv_of_the_wrong_length_is_rejected() {
    assert!(matches!(
        HlsKeyParser::parse(r#"#EXT-X-KEY:METHOD=AES-128,URI="https://e/k",IV=0x0102"#)
            .unwrap_err(),
        Error::Malformed {
            what: "EXT-X-KEY IV",
            ..
        }
    ));
}

/// The certificate fixtures are throwaway self-signed certificates generated
/// for this test alone. They are public halves only: no private key, and
/// nothing issued by Apple.
mod fixtures {
    /// An X.509 v1 certificate with a 2048-bit RSA key.
    pub const RSA_V1_CERT: &str = "308202a8308201900209008ea0f5127beb204e300d06092a864886f70d01010b050030163114301206035504030c0b6670732e6578616d706c65301e170d3236303832373036343833325a170d3236303932363036343833325a30163114301206035504030c0b6670732e6578616d706c6530820122300d06092a864886f70d01010105000382010f003082010a0282010100c1db3a4dcdd75c2df67342bd0485af5ea044c7d9d0340ca45b28d0054e446b403864be1094b06793bb40538ac7b27509e5da182e45fbe05e9d410ee96d0dcf7e4c93106ae648207c0bf96a45337a7dee6cd5502e2e13d3592bbc95d1154fba5bc87ca10ddb7ae51bdae157fbc730e6e482b378898bfe7cd62a02c005e95a4479d867acb7da8a8089f490bc1e382858ae1f880d1c2d1936ea3df611b9e7074a1bc77643c1107666eb3b0bab4e36c15600a82e8e3e03f7876229a257c28bb33f2ea701eded25228814c2530b2e28dffd5aab51b76d0aff0349f61e0bb3acc8c6903de94ea85b681125e97fd5286c988cef10ea496ee40e4fbd71d9155a8b3818ad0203010001300d06092a864886f70d01010b0500038201010006fbcf94c5667e8573176281d99dbf650d86b5a91cab3b57ec2101ab45695c47d181bb4f76eb10b2f2ba086e622e43ac797d864244d2b327a7c487de6f20771f65d131148b6735fe3ce2954e1090c54dd05467d19a4e467674c0d6e3b2b641eac76dbfc76a44dc5eea377044546d49af07a9eff433d29182cc107769ad43cb0f4556e55c276e6d1b45e7129a649bb2b516ec4b7f512cafc86549c022b1612481c0938a7035a7442a849fb771ca61656b0a76cc06323e32f4945d2abf81fba38cfefd7e2f4a119306dfd933be6249201648d44b347e130a3a08ec53830e199cfc82a7106b3fb7d4295e0d272f4d6aac40badd03f93892ecd72907faded5e2edef";
    /// The `SubjectPublicKeyInfo` of [`RSA_V1_CERT`], as OpenSSL extracts it.
    pub const RSA_V1_SPKI: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c1db3a4dcdd75c2df67342bd0485af5ea044c7d9d0340ca45b28d0054e446b403864be1094b06793bb40538ac7b27509e5da182e45fbe05e9d410ee96d0dcf7e4c93106ae648207c0bf96a45337a7dee6cd5502e2e13d3592bbc95d1154fba5bc87ca10ddb7ae51bdae157fbc730e6e482b378898bfe7cd62a02c005e95a4479d867acb7da8a8089f490bc1e382858ae1f880d1c2d1936ea3df611b9e7074a1bc77643c1107666eb3b0bab4e36c15600a82e8e3e03f7876229a257c28bb33f2ea701eded25228814c2530b2e28dffd5aab51b76d0aff0349f61e0bb3acc8c6903de94ea85b681125e97fd5286c988cef10ea496ee40e4fbd71d9155a8b3818ad0203010001";

    /// An X.509 v3 certificate — the shape a real FairPlay certificate has,
    /// with the optional `[0] EXPLICIT version` field present.
    pub const RSA_V3_CERT: &str = "308202f4308201dca003020102020900f3c9cc7b362d82b9300d06092a864886f70d01010b050030193117301506035504030c0e6670732d76332e6578616d706c65301e170d3236303832373036353134305a170d3236303932363036353134305a30193117301506035504030c0e6670732d76332e6578616d706c6530820122300d06092a864886f70d01010105000382010f003082010a0282010100d17c2e8d2961faac83c9f58049e70a9767e42fea0bd2403c887514cccd25df468babddc6aa535bfdcc94217077da9bd36a73f278bb41fcc60d13156acdcb57a2353f0b1c6848b2dbe15ef04e0259d0c116408a4da02ca666c8bcf5062152704b7a84c8f07122ad50c245ffb62a97e8507154890cae13e7ce67e808617168bdd8368ac8ec02b233cb6f66a2423ecda1dae448ebcbd7d74cbe9a1893e37569a09793eebe80ac82f2949781d9c6bd2a5fc9bc8c2a905444797ce1bfdddc1369ee74681446baacfbe5b84e100056e8419e3d82d95417292da311337f084dd5bbe85374ac135dbee834c069e0abbf5c52f636e41c416881da57009be5e557e796eab70203010001a33f303d300c0603551d130101ff04023000300e0603551d0f0101ff0404030205a0301d0603551d0e0416041477a088340b7b831b12ceec652e6d67e01955ada6300d06092a864886f70d01010b05000382010100214157435340d1839cbb27f70c21656726d2b19cf031846be31d5890b2498e15afcf9bab2feaaf6e889f4c30f23c3f934b7d72fdf110633d7bf7d1a038c151aec983ade33b6fc59207c18c1d2bfcf4f87bfd73c36b7a3a6ccfab8338fb269bf8774fed316ff162306703901151633d75f5e1213e23377a53ca94b038f804f0f5211d3afa5dd8321649dc3e3566db37620a46c5e0d97b37f1479594ccfcabe3d829968c2f9364f0910358046be737452e8e9569319d0a392c36f67b704df09831800dce997763f6b4237eec07768c7c81f670c4e03d780ef6815e203bd395784090ecc81a80905cc1614434d1c677b410fb12f528f9e669203d119ba199b53e0f";
    /// The `SubjectPublicKeyInfo` of [`RSA_V3_CERT`].
    pub const RSA_V3_SPKI: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100d17c2e8d2961faac83c9f58049e70a9767e42fea0bd2403c887514cccd25df468babddc6aa535bfdcc94217077da9bd36a73f278bb41fcc60d13156acdcb57a2353f0b1c6848b2dbe15ef04e0259d0c116408a4da02ca666c8bcf5062152704b7a84c8f07122ad50c245ffb62a97e8507154890cae13e7ce67e808617168bdd8368ac8ec02b233cb6f66a2423ecda1dae448ebcbd7d74cbe9a1893e37569a09793eebe80ac82f2949781d9c6bd2a5fc9bc8c2a905444797ce1bfdddc1369ee74681446baacfbe5b84e100056e8419e3d82d95417292da311337f084dd5bbe85374ac135dbee834c069e0abbf5c52f636e41c416881da57009be5e557e796eab70203010001";

    /// An X.509 v1 certificate with a P-256 key, whose `SubjectPublicKeyInfo`
    /// is short enough to use a short-form DER length.
    pub const EC_V1_CERT: &str = "308201203081c8020900f195a0b7e2ddc789300a06082a8648ce3d04030230193117301506035504030c0e6670732d65632e6578616d706c65301e170d3236303832373036353132365a170d3236303932363036353132365a30193117301506035504030c0e6670732d65632e6578616d706c653059301306072a8648ce3d020106082a8648ce3d030107034200042d2fcce000b4eb4af5628be976d24b2442bfc40a4851e6640ab89f735395712c6c7bbfd12c4d3f277e1f25f7047087a14bdf013a90567d29dc23ac1eae23d3f0300a06082a8648ce3d040302034700304402206b2994e7100a26d4a63165aebf0f65cd23f108fc3a699041e69618fd272a80670220081ea0b39d64f8d307b1e791a412d4f42bc63c41a01416e7a1f59b9bf822d8f2";
    /// The `SubjectPublicKeyInfo` of [`EC_V1_CERT`].
    pub const EC_V1_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200042d2fcce000b4eb4af5628be976d24b2442bfc40a4851e6640ab89f735395712c6c7bbfd12c4d3f277e1f25f7047087a14bdf013a90567d29dc23ac1eae23d3f0";
}

/// The whole point of the function: given a certificate, return the key inside
/// it. The scan-for-`30 82` implementation this replaces returned the *entire
/// certificate*, because the outermost `SEQUENCE` in any DER certificate is the
/// certificate itself — a caller who sent the result where a public key was
/// expected sent the whole file.
#[test]
fn extracts_the_subject_public_key_info_from_a_v1_certificate() {
    let certificate = hex::decode(fixtures::RSA_V1_CERT).unwrap();
    let expected = hex::decode(fixtures::RSA_V1_SPKI).unwrap();

    let key = FairPlayCertificate::extract_public_key(&certificate).unwrap();

    assert_eq!(key, expected);
    assert_ne!(key, certificate, "the whole certificate is not the key");
}

/// A real FairPlay certificate is v3, so the optional `[0] EXPLICIT version`
/// field sits before the serial number and has to be skipped.
#[test]
fn extracts_the_subject_public_key_info_from_a_v3_certificate() {
    let certificate = hex::decode(fixtures::RSA_V3_CERT).unwrap();
    let expected = hex::decode(fixtures::RSA_V3_SPKI).unwrap();

    assert_eq!(
        FairPlayCertificate::extract_public_key(&certificate).unwrap(),
        expected
    );
}

/// A P-256 `SubjectPublicKeyInfo` is 91 bytes, so its DER length is short-form
/// — one byte, no `82`. The old scan could not have found it at all.
#[test]
fn extracts_a_short_form_length_subject_public_key_info() {
    let certificate = hex::decode(fixtures::EC_V1_CERT).unwrap();
    let expected = hex::decode(fixtures::EC_V1_SPKI).unwrap();

    let key = FairPlayCertificate::extract_public_key(&certificate).unwrap();

    assert_eq!(key, expected);
    assert_eq!(key[1], 0x59, "short-form length, not 0x82");
}

/// Every prefix of a real certificate must be an error, never a panic.
#[test]
fn every_truncation_of_a_certificate_is_an_error_not_a_panic() {
    let certificate = hex::decode(fixtures::RSA_V3_CERT).unwrap();

    for length in 0..certificate.len() {
        assert!(
            FairPlayCertificate::extract_public_key(&certificate[..length]).is_err(),
            "a certificate truncated to {length} bytes parsed"
        );
    }

    assert!(FairPlayCertificate::extract_public_key(&certificate).is_ok());
}

/// A DER length marker with its length bytes past the end of the buffer.
#[test]
fn a_der_length_at_the_end_of_the_buffer_is_an_error_not_a_panic() {
    for bytes in [
        vec![0x30],
        vec![0x30, 0x82],
        vec![0x30, 0x82, 0x01],
        vec![0x30, 0x88],
        vec![0x30, 0x88, 0xFF, 0xFF, 0xFF],
    ] {
        assert!(
            matches!(
                FairPlayCertificate::extract_public_key(&bytes),
                Err(Error::Truncated { .. }) | Err(Error::Malformed { .. })
            ),
            "{bytes:02x?} was accepted"
        );
    }
}

/// DER forbids the indefinite length form, and a length field wider than a
/// machine word cannot be addressed. Both must be rejected before arithmetic.
#[test]
fn indefinite_and_oversized_der_lengths_are_rejected() {
    // 0x80 is the indefinite form: legal BER, never legal DER.
    assert!(matches!(
        FairPlayCertificate::extract_public_key(&[0x30, 0x80, 0x00, 0x00]).unwrap_err(),
        Error::Malformed { .. }
    ));

    // 0x89 announces nine length bytes, which no usize can hold.
    assert!(matches!(
        FairPlayCertificate::extract_public_key(&[
            0x30, 0x89, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
        ])
        .unwrap_err(),
        Error::Malformed { .. }
    ));

    // A length that fits the field but runs far past the buffer.
    assert!(matches!(
        FairPlayCertificate::extract_public_key(&[0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF]).unwrap_err(),
        Error::Truncated { .. }
    ));
}

/// A certificate whose outer `SEQUENCE` is well-formed but whose contents run
/// out before the public key is reached.
#[test]
fn a_certificate_that_ends_before_the_public_key_is_rejected() {
    // SEQUENCE { SEQUENCE { INTEGER 1 } } — a tbsCertificate with one field.
    let certificate = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01];

    assert!(FairPlayCertificate::extract_public_key(&certificate).is_err());
}

/// A tbsCertificate field that claims to run past the tbsCertificate must not
/// be read out of the signature that follows it.
#[test]
fn a_field_running_past_the_tbs_certificate_is_rejected() {
    let certificate = hex::decode(fixtures::RSA_V3_CERT).unwrap();
    let mut tampered = certificate.clone();

    // Shrink tbsCertificate's declared length so the fields inside it now run
    // past its own end. The bytes are all still present in the buffer.
    tampered[6] = 0x00;
    tampered[7] = 0x10;

    assert!(matches!(
        FairPlayCertificate::extract_public_key(&tampered).unwrap_err(),
        Error::Malformed { .. } | Error::Truncated { .. }
    ));
}

#[test]
fn a_certificate_with_no_der_sequence_is_rejected() {
    assert!(matches!(
        FairPlayCertificate::extract_public_key(&[0x00; 100]).unwrap_err(),
        Error::Malformed {
            what: "FairPlay certificate",
            ..
        }
    ));
}

/// A `30 82` pair in the last two bytes reached past the end of the slice in
/// the original implementation.
#[test]
fn a_marker_at_the_very_end_does_not_panic() {
    let mut certificate = vec![0x00; 32];
    certificate[30] = 0x30;
    certificate[31] = 0x82;

    assert!(FairPlayCertificate::extract_public_key(&certificate).is_err());
}

/// A `SEQUENCE` whose declared length runs past the end of the buffer is a
/// truncated certificate, not something to hunt past for a luckier structure.
#[test]
fn an_outer_sequence_longer_than_the_buffer_is_rejected() {
    let mut certificate = vec![0x00; 200];
    certificate[0] = 0x30;
    certificate[1] = 0x82;
    certificate[2] = 0xFF; // claims ~65k bytes
    certificate[3] = 0xFF;

    assert!(matches!(
        FairPlayCertificate::extract_public_key(&certificate).unwrap_err(),
        Error::Truncated { .. }
    ));
}

#[test]
fn an_empty_certificate_is_rejected() {
    assert!(FairPlayCertificate::extract_public_key(&[]).is_err());
}

#[test]
fn loading_a_certificate_that_is_not_there_is_an_io_error() {
    let error = FairPlayCertificate::load_from_file("/nonexistent/fairplay.cer").unwrap_err();
    assert!(matches!(error, Error::Io(_)));
}

#[test]
fn splits_fps_init_data_into_two_identifiers() {
    let blob = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18,
    ];

    let parsed = FpsInitData::parse(&blob).unwrap();

    assert_eq!(parsed.content_id, "AQIDBAUGBwg=");
    assert_eq!(parsed.key_id, "ERITFBUWFxg=");
}

#[test]
fn fps_init_data_ignores_bytes_past_the_first_sixteen() {
    let short = FpsInitData::parse(&[0xAB; 16]).unwrap();
    let long = FpsInitData::parse(&[0xAB; 64]).unwrap();

    assert_eq!(short, long);
}

#[test]
fn fps_init_data_shorter_than_sixteen_bytes_is_rejected() {
    assert!(matches!(
        FpsInitData::parse(&[0x00; 10]).unwrap_err(),
        Error::Truncated {
            needed: 16,
            available: 10,
            ..
        }
    ));
}
