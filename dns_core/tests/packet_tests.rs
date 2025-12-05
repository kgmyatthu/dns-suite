use std::net::Ipv4Addr;

use dns_core::{
    buffer::BytePacketBuffer,
    packet::DnsPacket,
    question::DnsQuestion,
    record::DnsRecord,
    types::{QueryType, ResultCode},
};

#[test]
fn packet_write_sets_counts_and_roundtrips() {
    let mut packet = DnsPacket::new();
    packet.header.id = 0x2222;
    packet.header.recursion_desired = true;
    packet.header.rescode = ResultCode::NOERROR;

    packet
        .questions
        .push(DnsQuestion::new("example.org".into(), QueryType::A));
    packet.answers.push(DnsRecord::A {
        domain: "example.org".into(),
        class: 1,
        ttl: 123,
        addr: Ipv4Addr::new(192, 0, 2, 123),
    });

    let mut buffer = BytePacketBuffer::new();
    packet.write(&mut buffer).unwrap();

    // Counts should be updated based on the contents before serialization
    assert_eq!(1, packet.header.questions);
    assert_eq!(1, packet.header.answers);
    assert_eq!(0, packet.header.authoritative_entries);
    assert_eq!(0, packet.header.resource_entries);

    buffer.seek(0);
    let parsed = DnsPacket::from_buffer(&mut buffer).unwrap();

    assert_eq!(packet.header.id, parsed.header.id);
    assert_eq!(packet.questions, parsed.questions);
    assert_eq!(packet.answers, parsed.answers);
}
