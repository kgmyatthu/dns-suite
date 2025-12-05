use dns_core::{buffer::BytePacketBuffer, header::DnsHeader, types::ResultCode};

#[test]
fn header_roundtrip_preserves_flags() {
    let mut header = DnsHeader::new();
    header.id = 0xABCD;
    header.recursion_desired = true;
    header.truncated_message = true;
    header.authoritative_answer = true;
    header.opcode = 5;
    header.response = true;
    header.rescode = ResultCode::SERVFAIL;
    header.checking_disabled = true;
    header.authed_data = true;
    header.z = true;
    header.recursion_available = true;
    header.questions = 2;
    header.answers = 3;
    header.authoritative_entries = 4;
    header.resource_entries = 5;

    let mut buffer = BytePacketBuffer::new();
    header.write(&mut buffer).unwrap();
    buffer.seek(0);

    let mut parsed = DnsHeader::new();
    parsed.read(&mut buffer).unwrap();
    assert_eq!(header.id, parsed.id);
    assert_eq!(header.recursion_desired, parsed.recursion_desired);
    assert_eq!(header.truncated_message, parsed.truncated_message);
    assert_eq!(header.authoritative_answer, parsed.authoritative_answer);
    assert_eq!(header.opcode, parsed.opcode);
    assert_eq!(header.response, parsed.response);
    assert_eq!(header.rescode, parsed.rescode);
    assert_eq!(header.checking_disabled, parsed.checking_disabled);
    assert_eq!(header.authed_data, parsed.authed_data);
    assert_eq!(header.z, parsed.z);
    assert_eq!(header.recursion_available, parsed.recursion_available);
    assert_eq!(header.questions, parsed.questions);
    assert_eq!(header.answers, parsed.answers);
    assert_eq!(header.authoritative_entries, parsed.authoritative_entries);
    assert_eq!(header.resource_entries, parsed.resource_entries);
}

#[test]
fn unknown_result_codes_default_to_noerror() {
    assert_eq!(ResultCode::NOERROR, ResultCode::from_num(42));
}
