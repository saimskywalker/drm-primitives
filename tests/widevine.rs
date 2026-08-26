//! `pssh` box generation and parsing.

use drm_primitives::widevine::{PsshBox, KEY_ID_LEN, WIDEVINE_SYSTEM_ID};
use drm_primitives::Error;

fn key_id(byte: u8) -> [u8; KEY_ID_LEN] {
    [byte; KEY_ID_LEN]
}

#[test]
fn a_v1_box_round_trips_one_key_id() {
    let id = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let bytes = PsshBox::widevine_v1(&[id]).to_bytes();

    assert_eq!(&bytes[4..8], b"pssh");

    let parsed = PsshBox::parse(&bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.key_ids, vec![id]);
    assert!(parsed.data.is_empty());
    assert!(parsed.is_widevine());
}

#[test]
fn a_v1_box_round_trips_several_key_ids() {
    let ids = [key_id(1), key_id(2), key_id(3)];
    let parsed = PsshBox::parse(&PsshBox::widevine_v1(&ids).to_bytes()).unwrap();

    assert_eq!(parsed.key_ids, ids.to_vec());
}

#[test]
fn a_v1_box_with_no_key_ids_is_valid() {
    let parsed = PsshBox::parse(&PsshBox::widevine_v1(&[]).to_bytes()).unwrap();

    assert_eq!(parsed.version, 1);
    assert!(parsed.key_ids.is_empty());
}

#[test]
fn a_v0_box_round_trips_its_payload() {
    let payload = b"an opaque widevine protobuf".to_vec();
    let parsed = PsshBox::parse(&PsshBox::widevine_v0(payload.clone()).to_bytes()).unwrap();

    assert_eq!(parsed.version, 0);
    assert_eq!(parsed.data, payload);
    assert!(parsed.key_ids.is_empty());
    assert!(parsed.is_widevine());
}

#[test]
fn a_v0_box_with_an_empty_payload_is_valid() {
    let parsed = PsshBox::parse(&PsshBox::widevine_v0(Vec::new()).to_bytes()).unwrap();

    assert_eq!(parsed.version, 0);
    assert!(parsed.data.is_empty());
}

/// The declared box size must be the real length, or a demuxer walking a `moov`
/// lands mid-box on the next read.
#[test]
fn the_declared_size_matches_the_serialised_length() {
    for bytes in [
        PsshBox::widevine_v1(&[key_id(1), key_id(2)]).to_bytes(),
        PsshBox::widevine_v0(b"payload".to_vec()).to_bytes(),
    ] {
        let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(declared, bytes.len());
    }
}

#[test]
fn the_system_id_is_the_registered_widevine_uuid() {
    let bytes = PsshBox::widevine_v1(&[key_id(1)]).to_bytes();

    assert_eq!(&bytes[12..28], &WIDEVINE_SYSTEM_ID[..]);
    assert_eq!(
        hex::encode(WIDEVINE_SYSTEM_ID),
        "edef8ba979d64acea3c827dcd51d21ed"
    );
}

/// The parser is system-agnostic on purpose: a PlayReady box parses, and
/// `is_widevine` is what distinguishes it.
#[test]
fn a_box_for_another_drm_system_parses_but_is_not_widevine() {
    let playready = [
        0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86, 0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F,
        0x95,
    ];
    let source = PsshBox {
        version: 0,
        flags: [0; 3],
        system_id: playready,
        key_ids: Vec::new(),
        data: b"playready payload".to_vec(),
    };

    let parsed = PsshBox::parse(&source.to_bytes()).unwrap();
    assert_eq!(parsed.system_id, playready);
    assert!(!parsed.is_widevine());
    assert_eq!(parsed, source);
}

/// A `pssh` box in a real buffer is followed by the next box, not by EOF.
#[test]
fn trailing_bytes_past_the_declared_size_are_ignored() {
    let mut buffer = PsshBox::widevine_v1(&[key_id(7)]).to_bytes();
    buffer.extend_from_slice(b"\x00\x00\x00\x08free");

    let parsed = PsshBox::parse(&buffer).unwrap();
    assert_eq!(parsed.key_ids, vec![key_id(7)]);
}

/// A declared size of zero means "to the end of the file" in ISO-BMFF.
#[test]
fn a_declared_size_of_zero_reads_to_the_end() {
    let mut bytes = PsshBox::widevine_v0(b"payload".to_vec()).to_bytes();
    bytes[0..4].copy_from_slice(&0u32.to_be_bytes());

    assert_eq!(PsshBox::parse(&bytes).unwrap().data, b"payload");
}

#[test]
fn a_box_shorter_than_the_header_is_rejected() {
    assert!(matches!(
        PsshBox::parse(&[0u8; 10]).unwrap_err(),
        Error::Truncated {
            needed: 32,
            available: 10,
            ..
        }
    ));
}

#[test]
fn a_box_whose_type_is_not_pssh_is_rejected() {
    assert!(matches!(
        PsshBox::parse(b"not_a_pssh_box_padded_to_thirty_two").unwrap_err(),
        Error::Malformed { .. }
    ));
}

#[test]
fn a_declared_size_past_the_end_of_the_buffer_is_rejected() {
    let mut bytes = PsshBox::widevine_v1(&[key_id(1)]).to_bytes();
    bytes[0..4].copy_from_slice(&9999u32.to_be_bytes());

    assert!(matches!(
        PsshBox::parse(&bytes).unwrap_err(),
        Error::Truncated { needed: 9999, .. }
    ));
}

#[test]
fn a_declared_size_smaller_than_the_header_is_rejected() {
    let mut bytes = PsshBox::widevine_v1(&[key_id(1)]).to_bytes();
    bytes[0..4].copy_from_slice(&20u32.to_be_bytes());

    assert!(matches!(
        PsshBox::parse(&bytes).unwrap_err(),
        Error::Malformed { .. }
    ));
}

#[test]
fn the_64_bit_largesize_form_is_rejected_rather_than_misread() {
    let mut bytes = PsshBox::widevine_v1(&[key_id(1)]).to_bytes();
    bytes[0..4].copy_from_slice(&1u32.to_be_bytes());

    assert!(matches!(
        PsshBox::parse(&bytes).unwrap_err(),
        Error::Malformed { .. }
    ));
}

/// A hostile key ID count must not index past the buffer or overflow the
/// length arithmetic.
#[test]
fn an_absurd_key_id_count_is_rejected_rather_than_panicking() {
    let mut bytes = PsshBox::widevine_v1(&[key_id(1)]).to_bytes();
    let len = bytes.len() as u32;
    bytes[0..4].copy_from_slice(&len.to_be_bytes());
    bytes[28..32].copy_from_slice(&u32::MAX.to_be_bytes());

    assert!(PsshBox::parse(&bytes).is_err());
}

#[test]
fn a_data_size_past_the_end_of_the_box_is_rejected() {
    let mut bytes = PsshBox::widevine_v0(b"payload".to_vec()).to_bytes();
    let len = bytes.len();
    bytes[28..32].copy_from_slice(&1000u32.to_be_bytes());
    bytes[0..4].copy_from_slice(&(len as u32).to_be_bytes());

    assert!(matches!(
        PsshBox::parse(&bytes).unwrap_err(),
        Error::Truncated { .. }
    ));
}

/// A v1 box truncated inside its key ID list — the shape a partial network
/// read produces.
#[test]
fn a_v1_box_cut_short_inside_its_key_id_list_is_rejected() {
    let full = PsshBox::widevine_v1(&[key_id(1), key_id(2)]).to_bytes();
    let mut cut = full[..full.len() - 20].to_vec();
    let len = cut.len() as u32;
    cut[0..4].copy_from_slice(&len.to_be_bytes());

    assert!(matches!(
        PsshBox::parse(&cut).unwrap_err(),
        Error::Truncated { .. }
    ));
}

#[test]
fn key_ids_are_not_written_for_a_v0_box() {
    let source = PsshBox {
        version: 0,
        flags: [0; 3],
        system_id: WIDEVINE_SYSTEM_ID,
        key_ids: vec![key_id(1)],
        data: Vec::new(),
    };

    let parsed = PsshBox::parse(&source.to_bytes()).unwrap();
    assert!(parsed.key_ids.is_empty());
}
