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
    let (server, domain, qtype) = parse_args()?;

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
    let qtype_display = display_query_type(qtype);
    let domain_display = display_domain(domain);

    println!(
        "; <<>> DiG <<>> @{} {} {}",
        server, domain_display, qtype_display
    );
    println!(";; global options: +cmd");
    println!(";; Got answer:\n");
    println!(
        ";; ->>HEADER<<- opcode: {}, status: {:?}, id: {}",
        packet.header.opcode, packet.header.rescode, packet.header.id
    );
    println!(
        ";; flags:{}{}{}{}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
        display_flag(" qr", packet.header.response),
        display_flag(" aa", packet.header.authoritative_answer),
        display_flag(" rd", packet.header.recursion_desired),
        display_flag(" ra", packet.header.recursion_available),
        packet.header.questions,
        packet.header.answers,
        packet.header.authoritative_entries,
        packet.header.resource_entries
    );

    println!("\n;; QUESTION SECTION:");
    for question in &packet.questions {
        println!(
            ";{}\t{}\t{}",
            display_domain(&question.name),
            display_class(1),
            display_query_type(question.qtype)
        );
    }

    if !packet.answers.is_empty() {
        println!("\n;; ANSWER SECTION:");
        for record in &packet.answers {
            println!("{}", display_record(record));
        }
    }

    if !packet.authorities.is_empty() {
        println!("\n;; AUTHORITY SECTION:");
        for record in &packet.authorities {
            println!("{}", display_record(record));
        }
    }

    if !packet.resources.is_empty() {
        println!("\n;; ADDITIONAL SECTION:");
        for record in &packet.resources {
            println!("{}", display_record(record));
        }
    }
}

fn parse_args() -> Result<(IpAddr, String, QueryType), Box<dyn std::error::Error>> {
    let mut server = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let mut domain: Option<String> = None;
    let mut qtype: Option<QueryType> = None;

    for raw_arg in env::args().skip(1) {
        if let Some(stripped) = raw_arg.strip_prefix('@') {
            server = stripped.parse()?;
            continue;
        }

        if domain.is_none() {
            domain = Some(raw_arg);
            continue;
        }

        if qtype.is_none() {
            qtype = Some(
                parse_query_type(&raw_arg)
                    .ok_or_else(|| format!("Unknown query type '{}'.", raw_arg))?,
            );
            continue;
        }
    }

    let domain = domain.ok_or_else(|| {
        "Usage: dig [@server] name [type]\n  example: dig @8.8.8.8 example.com A".to_string()
    })?;

    Ok((server, domain, qtype.unwrap_or(QueryType::A)))
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

fn display_class(class: u16) -> String {
    match class {
        1 => "IN".to_string(),
        2 => "CS".to_string(),
        3 => "CH".to_string(),
        4 => "HS".to_string(),
        value => format!("CLASS{}", value),
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
            domain,
            class,
            ttl,
            addr,
            ..
        } => format!(
            "{}\t{}\t{}\tA\t{}",
            display_domain(domain),
            ttl,
            display_class(*class),
            addr
        ),
        DnsRecord::AAAA {
            domain,
            addr,
            class,
            ttl,
            ..
        } => format!(
            "{}\t{}\t{}\tAAAA\t{}",
            display_domain(domain),
            ttl,
            display_class(*class),
            addr
        ),
        DnsRecord::MX {
            domain,
            ttl,
            priority,
            host,
            class,
            ..
        } => format!(
            "{}\t{}\t{}\tMX\t{}\t{}",
            display_domain(domain),
            ttl,
            display_class(*class),
            priority,
            display_domain(host)
        ),
        DnsRecord::NS {
            domain,
            ttl,
            host,
            class,
            ..
        } => format!(
            "{}\t{}\t{}\tNS\t{}",
            display_domain(domain),
            ttl,
            display_class(*class),
            display_domain(host)
        ),
        DnsRecord::CNAME {
            domain,
            ttl,
            host,
            class,
            ..
        } => format!(
            "{}\t{}\t{}\tCNAME\t{}",
            display_domain(domain),
            ttl,
            display_class(*class),
            display_domain(host)
        ),
        DnsRecord::UNKNOWN {
            domain,
            qtype,
            ttl,
            class,
            ..
        } => {
            let mut line = String::new();
            let _ = write!(
                &mut line,
                "{}\t{}\t{}\t{}",
                display_domain(domain),
                ttl,
                display_class(*class),
                display_query_type(*qtype)
            );
            line
        }
    }
}

fn display_domain(domain: &str) -> String {
    if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{}.", domain)
    }
}

fn display_flag(label: &str, present: bool) -> String {
    if present {
        label.to_string()
    } else {
        String::new()
    }
}

fn random_id() -> u16 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.subsec_nanos() & 0xFFFF) as u16
}
