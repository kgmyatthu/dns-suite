use std::env;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dns_core::buffer::BytePacketBuffer;
use dns_core::packet::DnsPacket;
use dns_core::question::DnsQuestion;
use dns_core::record::DnsRecord;
use dns_core::types::QueryType;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);

    let domain = match args.next() {
        Some(domain) => domain,
        None => {
            eprintln!("Usage: example <domain> [TYPE] [SERVER]");
            std::process::exit(1);
        }
    };

    let qtype = args
        .next()
        .as_deref()
        .and_then(parse_query_type)
        .unwrap_or(QueryType::A);

    let server = args
        .next()
        .map(|addr| addr.parse())
        .transpose()? // convert Option<Result<_, _>> to Result<Option<_>, _>
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

    let response = lookup(&domain, qtype, server)?;

    print_packet(&domain, qtype, server, &response);

    Ok(())
}

fn lookup(
    qname: &str,
    qtype: QueryType,
    server: IpAddr,
) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    let mut request = DnsPacket::new();
    request.header.id = random_id();
    request.header.recursion_desired = true;
    request
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    request.write(&mut req_buffer)?;

    let socket = match server {
        IpAddr::V4(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
        IpAddr::V6(_) => UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?,
    };
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.send_to(&req_buffer.buffer[..req_buffer.pos()], (server, 53))?;

    let mut resp_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut resp_buffer.buffer)?;

    DnsPacket::from_buffer(&mut resp_buffer)
}

fn print_packet(domain: &str, qtype: QueryType, server: IpAddr, packet: &DnsPacket) {
    println!(
        "; <<>> example <<>> {} {}",
        domain,
        display_query_type(qtype)
    );
    println!(";; SERVER: {}#53", server);
    println!(
        ";; ->>HEADER<<- opcode: {}, status: {:?}, id: {}",
        packet.header.opcode, packet.header.rescode, packet.header.id
    );
    println!(
        ";; flags: qr:{} rd:{} ra:{}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
        packet.header.response as u8,
        packet.header.recursion_desired as u8,
        packet.header.recursion_available as u8,
        packet.header.questions,
        packet.header.answers,
        packet.header.authoritative_entries,
        packet.header.resource_entries
    );

    println!("\n;; QUESTION SECTION:");
    for question in &packet.questions {
        println!(
            ";\t{}\tIN\t{}",
            question.name,
            display_query_type(question.qtype)
        );
    }

    println!("\n;; ANSWER SECTION:");
    for record in &packet.answers {
        println!("{}", display_record(record));
    }

    println!("\n;; AUTHORITY SECTION:");
    for record in &packet.authorities {
        println!("{}", display_record(record));
    }

    println!("\n;; ADDITIONAL SECTION:");
    for record in &packet.resources {
        println!("{}", display_record(record));
    }
}

fn parse_query_type(name: &str) -> Option<QueryType> {
    match name.to_uppercase().as_str() {
        "A" => Some(QueryType::A),
        "AAAA" => Some(QueryType::AAAA),
        "MX" => Some(QueryType::MX),
        "NS" => Some(QueryType::NS),
        "CNAME" => Some(QueryType::CNAME),
        _ => None,
    }
}

fn display_query_type(qtype: QueryType) -> String {
    match qtype {
        QueryType::A => "A",
        QueryType::AAAA => "AAAA",
        QueryType::MX => "MX",
        QueryType::NS => "NS",
        QueryType::CNAME => "CNAME",
        QueryType::UNKNOWN(value) => return format!("TYPE{}", value),
    }
    .to_string()
}

fn display_record(record: &DnsRecord) -> String {
    match record {
        DnsRecord::A {
            domain, ttl, addr, ..
        } => format!("{}\t{}\tIN\tA\t{}", domain, ttl, addr),
        DnsRecord::AAAA {
            domain, ttl, addr, ..
        } => format!("{}\t{}\tIN\tAAAA\t{}", domain, ttl, addr),
        DnsRecord::MX {
            domain,
            ttl,
            priority,
            host,
            ..
        } => format!("{}\t{}\tIN\tMX\t{}\t{}", domain, ttl, priority, host),
        DnsRecord::NS {
            domain, ttl, host, ..
        } => format!("{}\t{}\tIN\tNS\t{}", domain, ttl, host),
        DnsRecord::CNAME {
            domain, ttl, host, ..
        } => format!("{}\t{}\tIN\tCNAME\t{}", domain, ttl, host),
        DnsRecord::UNKNOWN {
            domain, qtype, ttl, ..
        } => {
            let mut line = String::new();
            let _ = write!(
                &mut line,
                "{}\t{}\tIN\t{}",
                domain,
                ttl,
                display_query_type(*qtype)
            );
            line
        }
    }
}

fn random_id() -> u16 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.subsec_nanos() & 0xFFFF) as u16
}
