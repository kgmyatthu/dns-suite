use std::net::Ipv6Addr;

use dns_core::{buffer::BytePacketBuffer, record::DnsRecord, types::QueryType};

#[test]
fn aaaa_record_roundtrip() {
    let record = DnsRecord::AAAA {
        domain: "ipv6.test".into(),
        addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        class: 1,
        ttl: 600,
    };

    let mut buffer = BytePacketBuffer::new();
    record.write(&mut buffer).unwrap();
    buffer.seek(0);

    let parsed = DnsRecord::read(&mut buffer).unwrap();
    assert_eq!(record, parsed);
}

#[test]
fn txt_record_errors_when_length_exceeds_rdata() {
    let mut buffer = BytePacketBuffer::new();
    buffer.write_qname("txt.example").unwrap();
    buffer.write_u16(QueryType::TXT.to_num()).unwrap();
    buffer.write_u16(1).unwrap();
    buffer.write_u32(0).unwrap();
    buffer.write_u16(5).unwrap(); // rdata length claims 5 bytes

    buffer.write_u8(10).unwrap(); // txt length makes the record invalid

    buffer.seek(0);
    assert!(DnsRecord::read(&mut buffer).is_err());
}
