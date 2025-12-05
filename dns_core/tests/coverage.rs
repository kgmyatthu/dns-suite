use std::net::{Ipv4Addr, Ipv6Addr};

use dns_core::{
    buffer::BytePacketBuffer,
    buffer::MAX_PACKET_SIZE,
    header::DnsHeader,
    packet::DnsPacket,
    question::DnsQuestion,
    record::DnsRecord,
    types::{QueryType, ResultCode},
};

fn build_test_packet() -> DnsPacket {
    let mut packet = DnsPacket::new();

    packet.header.id = 0x1234;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.authoritative_answer = true;
    packet.header.truncated_message = true;
    packet.header.opcode = 3;
    packet.header.response = true;
    packet.header.rescode = ResultCode::NXDOMAIN;

    packet
        .questions
        .push(DnsQuestion::new("example.com".into(), QueryType::A));

    packet.answers.push(DnsRecord::A {
        domain: "example.com".into(),
        class: 1,
        ttl: 60,
        addr: Ipv4Addr::new(192, 0, 2, 1),
    });

    packet.authorities.push(DnsRecord::NS {
        domain: "example.com".into(),
        class: 1,
        host: "ns1.example.com".into(),
        ttl: 60,
    });

    packet.resources.push(DnsRecord::AAAA {
        domain: "example.com".into(),
        addr: Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111),
        class: 1,
        ttl: 60,
    });

    packet.resources.push(DnsRecord::MX {
        domain: "example.com".into(),
        priority: 10,
        class: 1,
        host: "mail.example.com".into(),
        ttl: 60,
    });

    packet.resources.push(DnsRecord::CNAME {
        domain: "alias.example.com".into(),
        host: "example.com".into(),
        class: 1,
        ttl: 30,
    });

    packet
}

#[test]
fn byte_packet_buffer_boundary_conditions() {
    let mut buffer = BytePacketBuffer::new();

    buffer.write_u8(0x12).unwrap();
    buffer.write_u16(0x3456).unwrap();
    buffer.write_u32(0x789ABCDE).unwrap();
    buffer.seek(0);
    assert_eq!(0x12, buffer.read().unwrap());
    assert_eq!(0x3456, buffer.read_u16().unwrap());
    assert_eq!(0x789ABCDE, buffer.read_u32().unwrap());

    buffer.step(10);
    assert_eq!(17, buffer.pos());
    buffer.set(5, 0xAA).unwrap();
    assert_eq!(0xAA, buffer.get(5).unwrap());

    buffer.seek(MAX_PACKET_SIZE - 1);
    assert!(buffer.write_u8(0xFF).is_ok());
    assert!(buffer.write_u8(0xEE).is_err());
    assert!(buffer.get_range(MAX_PACKET_SIZE - 2, 5).is_err());
}

#[test]
fn qname_roundtrip_and_pointer_behaviour() {
    let mut buffer = BytePacketBuffer::new();
    buffer.write_qname("MiXeD.Case.Test").unwrap();
    let pointer_location = buffer.pos();
    buffer.write_u8(0xC0).unwrap();
    buffer.write_u8(0x00).unwrap();

    buffer.seek(0);
    let mut out = String::new();
    buffer.read_qname(&mut out).unwrap();
    assert_eq!("mixed.case.test", out);

    buffer.seek(pointer_location);
    let mut pointer_out = String::new();
    buffer.read_qname(&mut pointer_out).unwrap();
    assert_eq!("mixed.case.test", pointer_out);

    let mut loop_buffer = BytePacketBuffer::new();
    loop_buffer.buffer[0] = 0xC0;
    loop_buffer.buffer[1] = 0x00;
    loop_buffer.seek(0);
    let mut loop_out = String::new();
    assert!(loop_buffer.read_qname(&mut loop_out).is_err());
}

#[test]
fn header_and_question_roundtrip() {
    let mut header = DnsHeader::new();
    header.id = 0xBEEF;
    header.recursion_desired = true;
    header.truncated_message = true;
    header.authoritative_answer = true;
    header.opcode = 2;
    header.response = true;
    header.rescode = ResultCode::REFUSED;
    header.checking_disabled = true;
    header.authed_data = true;
    header.z = true;
    header.recursion_available = true;

    header.questions = 2;
    header.answers = 1;
    header.authoritative_entries = 3;
    header.resource_entries = 4;

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

    let question = DnsQuestion::new("example.com".into(), QueryType::AAAA);
    let mut qbuffer = BytePacketBuffer::new();
    question.write(&mut qbuffer).unwrap();
    qbuffer.seek(0);

    let mut parsed_question = DnsQuestion::new(String::new(), QueryType::UNKNOWN(0));
    parsed_question.read(&mut qbuffer).unwrap();
    assert_eq!(question, parsed_question);
}

#[test]
fn records_read_and_write_roundtrip() {
    let records = vec![
        DnsRecord::A {
            domain: "example.com".into(),
            class: 1,
            ttl: 120,
            addr: Ipv4Addr::new(203, 0, 113, 5),
        },
        DnsRecord::NS {
            domain: "example.com".into(),
            class: 1,
            host: "ns.example.com".into(),
            ttl: 240,
        },
        DnsRecord::CNAME {
            domain: "alias.example.com".into(),
            class: 1,
            host: "example.com".into(),
            ttl: 360,
        },
        DnsRecord::MX {
            domain: "example.com".into(),
            priority: 5,
            class: 1,
            host: "mail.example.com".into(),
            ttl: 180,
        },
        DnsRecord::AAAA {
            domain: "ipv6.example.com".into(),
            addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            class: 1,
            ttl: 60,
        },
        DnsRecord::UNKNOWN {
            domain: "weird.example.com".into(),
            qtype: QueryType::UNKNOWN(65000),
            class: 1,
            ttl: 0,
            data: vec![1, 2, 3, 4],
        },
    ];

    for record in records {
        let mut buffer = BytePacketBuffer::new();
        let _ = record.write(&mut buffer);
        buffer.seek(0);
        let parsed = DnsRecord::read(&mut buffer).unwrap();
        match (&record, &parsed) {
            (
                DnsRecord::UNKNOWN {
                    domain: original,
                    qtype,
                    class,
                    ttl,
                    data,
                },
                DnsRecord::UNKNOWN {
                    domain,
                    qtype: pq,
                    class: pc,
                    ttl: pt,
                    data: pd,
                },
            ) => {
                assert_eq!(original, domain);
                assert_eq!(qtype, pq);
                assert_eq!(class, pc);
                assert_eq!(ttl, pt);
                assert_eq!(data, pd);
            }
            _ => assert_eq!(record, parsed),
        }
    }
}

#[test]
fn full_packet_write_and_parse() {
    let mut packet = build_test_packet();
    let mut buffer = BytePacketBuffer::new();
    packet.write(&mut buffer).unwrap();

    buffer.seek(0);
    let parsed = DnsPacket::from_buffer(&mut buffer).unwrap();

    assert_eq!(packet.header.id, parsed.header.id);
    assert_eq!(
        packet.header.recursion_desired,
        parsed.header.recursion_desired
    );
    assert_eq!(
        packet.header.recursion_available,
        parsed.header.recursion_available
    );
    assert_eq!(
        packet.header.authoritative_answer,
        parsed.header.authoritative_answer
    );
    assert_eq!(packet.questions, parsed.questions);
    assert_eq!(packet.answers, parsed.answers);
    assert_eq!(packet.authorities, parsed.authorities);
    assert_eq!(packet.resources, parsed.resources);
}

#[test]
fn invalid_qname_rejected() {
    let mut buffer = BytePacketBuffer::new();
    let oversized_label = "a".repeat(64) + ".com";
    assert!(buffer.write_qname(&oversized_label).is_err());
}
