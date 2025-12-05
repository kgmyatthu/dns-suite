use dns_core::{buffer::BytePacketBuffer, question::DnsQuestion, types::QueryType};

#[test]
fn question_write_and_read_roundtrip() {
    let question = DnsQuestion::new("rust-lang.org".into(), QueryType::MX);
    let mut buffer = BytePacketBuffer::new();
    question.write(&mut buffer).unwrap();
    let written_position = buffer.pos();

    buffer.seek(0);
    let mut parsed = DnsQuestion::new(String::new(), QueryType::UNKNOWN(0));
    parsed.read(&mut buffer).unwrap();

    assert_eq!(question, parsed);
    assert_eq!(written_position, buffer.pos());
}
