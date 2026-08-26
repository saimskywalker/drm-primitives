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

#[test]
fn extracts_a_der_sequence_from_a_certificate() {
    let mut certificate = vec![0x00; 300];
    certificate[10] = 0x30;
    certificate[11] = 0x82;
    certificate[12] = 0x00;
    certificate[13] = 0x50; // 80 bytes of content

    let key = FairPlayCertificate::extract_public_key(&certificate).unwrap();

    assert_eq!(key.len(), 84); // 4 header bytes plus 80
    assert_eq!(&key[..2], &[0x30, 0x82]);
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

/// A first marker whose declared length runs past the end must not shadow a
/// valid structure later in the file.
#[test]
fn a_marker_with_an_impossible_length_is_skipped_for_the_next_one() {
    let mut certificate = vec![0x00; 200];
    certificate[0] = 0x30;
    certificate[1] = 0x82;
    certificate[2] = 0xFF; // claims ~65k bytes
    certificate[3] = 0xFF;
    certificate[50] = 0x30;
    certificate[51] = 0x82;
    certificate[52] = 0x00;
    certificate[53] = 0x20; // 32 bytes

    let key = FairPlayCertificate::extract_public_key(&certificate).unwrap();
    assert_eq!(key.len(), 36);
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
