use super::*;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/channel-exchange-v3.json"
    ))
    .unwrap()
}
fn bytes(value: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().unwrap()).unwrap()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One ABI ownership lifecycle, including failure, replay and child handles outliving their session"
)]
fn binary_abi_authentication_ownership_and_fail_closed_boundaries() {
    let vector = fixture();
    let root = bytes(&vector, "root_hex");
    let id = bytes(&vector, "session_id_hex");
    let initial = bytes(&vector, "initial_private_hex");
    // SAFETY: every pointer below refers to live owned storage, outputs are
    // disjoint, and handles/buffers are each released once after use.
    unsafe {
        assert_eq!(
            stogas_channel_session_new(
                root.as_ptr(),
                id.as_ptr(),
                initial.as_ptr(),
                1152,
                ptr::null_mut()
            ),
            1
        );
        let mut session = ptr::null_mut();
        assert_eq!(
            stogas_channel_session_new(
                ptr::null(),
                id.as_ptr(),
                initial.as_ptr(),
                1152,
                &raw mut session
            ),
            1
        );
        assert!(session.is_null());
        assert_eq!(
            stogas_channel_session_new(
                root.as_ptr(),
                id.as_ptr(),
                initial.as_ptr(),
                33,
                &raw mut session
            ),
            3
        );
        assert!(session.is_null());
        assert_eq!(
            stogas_channel_session_new(
                root.as_ptr(),
                id.as_ptr(),
                initial.as_ptr(),
                1152,
                &raw mut session
            ),
            0
        );
        let (mut reader, mut writer) = (ptr::null_mut(), ptr::null_mut());
        let (mut offset, mut len) = (0, 0);
        let start = bytes(&vector["request"][0], "encoded_hex");
        let mut forged = start.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            stogas_channel_accept(
                session,
                0,
                forged.as_mut_ptr(),
                forged.len(),
                0,
                &raw mut reader,
                &raw mut writer,
                &raw mut offset,
                &raw mut len
            ),
            2
        );
        assert!(reader.is_null() && writer.is_null());
        assert_eq!((offset, len), (0, 0));
        let mut encoded = start.clone();
        assert_eq!(
            stogas_channel_accept(
                session,
                0,
                encoded.as_mut_ptr(),
                encoded.len(),
                0,
                &raw mut reader,
                &raw mut writer,
                &raw mut offset,
                &raw mut len
            ),
            0
        );
        assert_eq!(
            &encoded[offset..offset + len],
            bytes(&vector["request"][0], "plaintext_hex")
        );
        let (mut replay_reader, mut replay_writer) = (ptr::null_mut(), ptr::null_mut());
        let mut replay = start;
        assert_eq!(
            stogas_channel_accept(
                session,
                0,
                replay.as_mut_ptr(),
                replay.len(),
                0,
                &raw mut replay_reader,
                &raw mut replay_writer,
                &raw mut offset,
                &raw mut len
            ),
            1
        );
        assert!(replay_reader.is_null() && replay_writer.is_null());
        stogas_channel_session_free(session);
        for record in vector["request"].as_array().unwrap().iter().skip(1) {
            let mut encoded = bytes(record, "encoded_hex");
            let mut kind = 0;
            assert_eq!(
                stogas_channel_open(
                    reader,
                    encoded.as_mut_ptr(),
                    encoded.len(),
                    &raw mut kind,
                    &raw mut offset,
                    &raw mut len
                ),
                0
            );
            assert_eq!(u64::from(kind), record["kind"].as_u64().unwrap());
            assert_eq!(
                &encoded[offset..offset + len],
                bytes(record, "plaintext_hex")
            );
        }
        assert_eq!(stogas_channel_complete(reader), 0);
        stogas_channel_reader_free(reader);
        for record in vector["response"].as_array().unwrap() {
            let plain = bytes(record, "plaintext_hex");
            let mut output = StogasChannelBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            assert_eq!(
                stogas_channel_seal(
                    writer,
                    u8::try_from(record["kind"].as_u64().unwrap()).unwrap(),
                    plain.as_ptr(),
                    plain.len(),
                    &raw mut output
                ),
                0
            );
            let encoded = slice::from_raw_parts(output.data, output.len);
            assert_eq!(
                u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize,
                encoded.len()
            );
            let prefix = if record["kind"] == 1 {
                6 + usize::from(u16::from_be_bytes(encoded[4..6].try_into().unwrap()))
            } else {
                4
            };
            assert_eq!(encoded.len(), prefix + plain.len() + 17);
            stogas_channel_buffer_free(output);
        }
        let mut output = StogasChannelBuffer {
            data: ptr::null_mut(),
            len: 0,
        };
        assert_ne!(
            stogas_channel_seal(writer, 1, ptr::null(), 0, &raw mut output),
            0
        );
        assert!(output.data.is_null());
        stogas_channel_writer_free(writer);
        stogas_channel_session_free(ptr::null_mut());
        stogas_channel_reader_free(ptr::null_mut());
        stogas_channel_writer_free(ptr::null_mut());
    }
}

#[test]
fn invalid_binary_arguments_close_record_owners_and_panics_have_a_distinct_status() {
    assert_eq!(status(|| panic!("contained boundary panic")), 255);
    let vector = fixture();
    let root = bytes(&vector, "root_hex");
    let id = bytes(&vector, "session_id_hex");
    let initial = bytes(&vector, "initial_private_hex");
    for kind in [0, 5, 255] {
        // SAFETY: all inputs and disjoint outputs remain live through each call;
        // each successfully allocated handle is returned exactly once.
        unsafe {
            let mut session = ptr::null_mut();
            assert_eq!(
                stogas_channel_session_new(
                    root.as_ptr(),
                    id.as_ptr(),
                    initial.as_ptr(),
                    1152,
                    &raw mut session
                ),
                0
            );
            let (mut reader, mut writer) = (ptr::null_mut(), ptr::null_mut());
            let (mut offset, mut len) = (0, 0);
            let mut start = bytes(&vector["request"][0], "encoded_hex");
            assert_eq!(
                stogas_channel_accept(
                    session,
                    0,
                    start.as_mut_ptr(),
                    start.len(),
                    0,
                    &raw mut reader,
                    &raw mut writer,
                    &raw mut offset,
                    &raw mut len
                ),
                0
            );
            let mut output = StogasChannelBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            assert_eq!(
                stogas_channel_seal(writer, kind, ptr::null(), 0, &raw mut output),
                1
            );
            assert_eq!(
                stogas_channel_seal(writer, 1, ptr::null(), 0, &raw mut output),
                4
            );
            let mut actual = 0;
            assert_eq!(
                stogas_channel_open(
                    reader,
                    ptr::null_mut(),
                    0,
                    &raw mut actual,
                    &raw mut offset,
                    &raw mut len
                ),
                1
            );
            assert_ne!(stogas_channel_complete(reader), 0);
            stogas_channel_session_free(session);
            stogas_channel_reader_free(reader);
            stogas_channel_writer_free(writer);
        }
    }
}

#[test]
fn setup_key_outputs_reject_missing_storage() {
    let mut private = [0; 32];
    let mut public = [0; 32];
    // SAFETY: the valid arguments point to disjoint 32-byte arrays.
    unsafe {
        assert_eq!(
            stogas_channel_key_generate(ptr::null_mut(), public.as_mut_ptr()),
            1
        );
        assert_eq!(
            stogas_channel_key_generate(private.as_mut_ptr(), ptr::null_mut()),
            1
        );
        assert_eq!(
            stogas_channel_key_generate(private.as_mut_ptr(), public.as_mut_ptr()),
            0
        );
        assert_ne!(public, [0; 32]);
    }
}
