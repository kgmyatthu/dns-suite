use std::env;
use std::fmt::Write as _;
use std::io::ErrorKind;
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
    let (response_size, _) = socket.recv_from(&mut resp_buffer.buffer)?;
    resp_buffer.set_size(response_size);

    DnsPacket::from_buffer(&mut resp_buffer)
}

fn print_packet(domain: &str, qtype: QueryType, server: IpAddr, packet: &DnsPacket) {
    let qtype_display = display_query_type(qtype);
    let domain_display = display_domain(domain);

    println!("; <<>> DiG <<>> @{server} {domain_display} {qtype_display}");
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
                    .ok_or_else(|| format!("Unknown query type '{raw_arg}'."))?,
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
    let normalized = name.to_uppercase().replace(['-', '_'], "");

    let parsed = match normalized.as_str() {
        "A" => Some(QueryType::A),
        "NS" => Some(QueryType::NS),
        "CNAME" => Some(QueryType::CNAME),
        "SOA" => Some(QueryType::SOA),
        "PTR" => Some(QueryType::PTR),
        "HINFO" => Some(QueryType::HINFO),
        "MINFO" => Some(QueryType::MINFO),
        "MX" => Some(QueryType::MX),
        "TXT" => Some(QueryType::TXT),
        "RP" => Some(QueryType::RP),
        "AFSDB" => Some(QueryType::AFSDB),
        "X25" => Some(QueryType::X25),
        "ISDN" => Some(QueryType::ISDN),
        "RT" => Some(QueryType::RT),
        "NSAP" => Some(QueryType::NSAP),
        "NSAPPTR" => Some(QueryType::NsapPtr),
        "SIG" => Some(QueryType::SIG),
        "KEY" => Some(QueryType::KEY),
        "PX" => Some(QueryType::PX),
        "AAAA" => Some(QueryType::AAAA),
        "LOC" => Some(QueryType::LOC),
        "SRV" => Some(QueryType::SRV),
        "NAPTR" => Some(QueryType::NAPTR),
        "KX" => Some(QueryType::KX),
        "CERT" => Some(QueryType::CERT),
        "DNAME" => Some(QueryType::DNAME),
        "OPT" => Some(QueryType::OPT),
        "APL" => Some(QueryType::APL),
        "DS" => Some(QueryType::DS),
        "SSHFP" => Some(QueryType::SSHFP),
        "IPSECKEY" => Some(QueryType::IPSECKEY),
        "RRSIG" => Some(QueryType::RRSIG),
        "NSEC" => Some(QueryType::NSEC),
        "DNSKEY" => Some(QueryType::DNSKEY),
        "DHCID" => Some(QueryType::DHCID),
        "NSEC3" => Some(QueryType::NSEC3),
        "NSEC3PARAM" => Some(QueryType::NSEC3PARAM),
        "TLSA" => Some(QueryType::TLSA),
        "SMIMEA" => Some(QueryType::SMIMEA),
        "HIP" => Some(QueryType::HIP),
        "CDS" => Some(QueryType::CDS),
        "CDNSKEY" => Some(QueryType::CDNSKEY),
        "OPENPGPKEY" => Some(QueryType::OPENPGPKEY),
        "CSYNC" => Some(QueryType::CSYNC),
        "ZONEMD" => Some(QueryType::ZONEMD),
        "SVCB" => Some(QueryType::SVCB),
        "HTTPS" => Some(QueryType::HTTPS),
        "SPF" => Some(QueryType::SPF),
        "NID" => Some(QueryType::NID),
        "L32" => Some(QueryType::L32),
        "L64" => Some(QueryType::L64),
        "LP" => Some(QueryType::LP),
        "EUI48" => Some(QueryType::EUI48),
        "EUI64" => Some(QueryType::EUI64),
        "TKEY" => Some(QueryType::TKEY),
        "TSIG" => Some(QueryType::TSIG),
        "IXFR" => Some(QueryType::IXFR),
        "AXFR" => Some(QueryType::AXFR),
        "ANY" => Some(QueryType::ANY),
        "URI" => Some(QueryType::URI),
        "CAA" => Some(QueryType::CAA),
        "AVC" => Some(QueryType::AVC),
        "DOA" => Some(QueryType::DOA),
        "AMTRELAY" => Some(QueryType::AMTRELAY),
        "TA" => Some(QueryType::TA),
        "DLV" => Some(QueryType::DLV),
        _ => None,
    };

    parsed.or_else(|| name.parse::<u16>().ok().map(QueryType::from_num))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    const ALL_QUERY_TYPES: &[QueryType] = &[
        QueryType::A,
        QueryType::NS,
        QueryType::CNAME,
        QueryType::SOA,
        QueryType::PTR,
        QueryType::HINFO,
        QueryType::MINFO,
        QueryType::MX,
        QueryType::TXT,
        QueryType::RP,
        QueryType::AFSDB,
        QueryType::X25,
        QueryType::ISDN,
        QueryType::RT,
        QueryType::NSAP,
        QueryType::NsapPtr,
        QueryType::SIG,
        QueryType::KEY,
        QueryType::PX,
        QueryType::AAAA,
        QueryType::LOC,
        QueryType::SRV,
        QueryType::NAPTR,
        QueryType::KX,
        QueryType::CERT,
        QueryType::DNAME,
        QueryType::OPT,
        QueryType::APL,
        QueryType::DS,
        QueryType::SSHFP,
        QueryType::IPSECKEY,
        QueryType::RRSIG,
        QueryType::NSEC,
        QueryType::DNSKEY,
        QueryType::DHCID,
        QueryType::NSEC3,
        QueryType::NSEC3PARAM,
        QueryType::TLSA,
        QueryType::SMIMEA,
        QueryType::HIP,
        QueryType::CDS,
        QueryType::CDNSKEY,
        QueryType::OPENPGPKEY,
        QueryType::CSYNC,
        QueryType::ZONEMD,
        QueryType::SVCB,
        QueryType::HTTPS,
        QueryType::SPF,
        QueryType::NID,
        QueryType::L32,
        QueryType::L64,
        QueryType::LP,
        QueryType::EUI48,
        QueryType::EUI64,
        QueryType::TKEY,
        QueryType::TSIG,
        QueryType::IXFR,
        QueryType::AXFR,
        QueryType::ANY,
        QueryType::URI,
        QueryType::CAA,
        QueryType::AVC,
        QueryType::DOA,
        QueryType::AMTRELAY,
        QueryType::TA,
        QueryType::DLV,
    ];

    #[test]
    fn parses_all_query_type_names() {
        let names = [
            "A",
            "NS",
            "CNAME",
            "SOA",
            "PTR",
            "HINFO",
            "MINFO",
            "MX",
            "TXT",
            "RP",
            "AFSDB",
            "X25",
            "ISDN",
            "RT",
            "NSAP",
            "NSAP-PTR",
            "SIG",
            "KEY",
            "PX",
            "AAAA",
            "LOC",
            "SRV",
            "NAPTR",
            "KX",
            "CERT",
            "DNAME",
            "OPT",
            "APL",
            "DS",
            "SSHFP",
            "IPSECKEY",
            "RRSIG",
            "NSEC",
            "DNSKEY",
            "DHCID",
            "NSEC3",
            "NSEC3PARAM",
            "TLSA",
            "SMIMEA",
            "HIP",
            "CDS",
            "CDNSKEY",
            "OPENPGPKEY",
            "CSYNC",
            "ZONEMD",
            "SVCB",
            "HTTPS",
            "SPF",
            "NID",
            "L32",
            "L64",
            "LP",
            "EUI48",
            "EUI64",
            "TKEY",
            "TSIG",
            "IXFR",
            "AXFR",
            "ANY",
            "URI",
            "CAA",
            "AVC",
            "DOA",
            "AMTRELAY",
            "TA",
            "DLV",
        ];

        for (name, &qtype) in names.iter().zip(ALL_QUERY_TYPES.iter()) {
            assert_eq!(
                parse_query_type(name),
                Some(qtype),
                "expected '{name}' to parse as {qtype:?}"
            );
        }
    }

    #[test]
    fn queries_google_for_each_supported_type() {
        for &qtype in ALL_QUERY_TYPES {
            let response = lookup("google.com", qtype, GOOGLE_DNS);
            if let Err(err) = response {
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io_err| io_err.kind() == ErrorKind::NetworkUnreachable)
                {
                    eprintln!("Skipping network-dependent test: {err}");
                    return;
                }

                panic!("lookup failed for {qtype:?}: {err:?}");
            }
        }
    }
}

fn display_class(class: u16) -> String {
    match class {
        1 => "IN".to_string(),
        2 => "CS".to_string(),
        3 => "CH".to_string(),
        4 => "HS".to_string(),
        value => format!("CLASS{value}"),
    }
}

fn display_query_type(qtype: QueryType) -> String {
    match qtype {
        QueryType::UNKNOWN(value) => format!("TYPE{value}"),
        QueryType::A => "A".to_string(),
        QueryType::NS => "NS".to_string(),
        QueryType::CNAME => "CNAME".to_string(),
        QueryType::SOA => "SOA".to_string(),
        QueryType::PTR => "PTR".to_string(),
        QueryType::HINFO => "HINFO".to_string(),
        QueryType::MINFO => "MINFO".to_string(),
        QueryType::MX => "MX".to_string(),
        QueryType::TXT => "TXT".to_string(),
        QueryType::RP => "RP".to_string(),
        QueryType::AFSDB => "AFSDB".to_string(),
        QueryType::X25 => "X25".to_string(),
        QueryType::ISDN => "ISDN".to_string(),
        QueryType::RT => "RT".to_string(),
        QueryType::NSAP => "NSAP".to_string(),
        QueryType::NsapPtr => "NSAP-PTR".to_string(),
        QueryType::SIG => "SIG".to_string(),
        QueryType::KEY => "KEY".to_string(),
        QueryType::PX => "PX".to_string(),
        QueryType::AAAA => "AAAA".to_string(),
        QueryType::LOC => "LOC".to_string(),
        QueryType::SRV => "SRV".to_string(),
        QueryType::NAPTR => "NAPTR".to_string(),
        QueryType::KX => "KX".to_string(),
        QueryType::CERT => "CERT".to_string(),
        QueryType::DNAME => "DNAME".to_string(),
        QueryType::OPT => "OPT".to_string(),
        QueryType::APL => "APL".to_string(),
        QueryType::DS => "DS".to_string(),
        QueryType::SSHFP => "SSHFP".to_string(),
        QueryType::IPSECKEY => "IPSECKEY".to_string(),
        QueryType::RRSIG => "RRSIG".to_string(),
        QueryType::NSEC => "NSEC".to_string(),
        QueryType::DNSKEY => "DNSKEY".to_string(),
        QueryType::DHCID => "DHCID".to_string(),
        QueryType::NSEC3 => "NSEC3".to_string(),
        QueryType::NSEC3PARAM => "NSEC3PARAM".to_string(),
        QueryType::TLSA => "TLSA".to_string(),
        QueryType::SMIMEA => "SMIMEA".to_string(),
        QueryType::HIP => "HIP".to_string(),
        QueryType::CDS => "CDS".to_string(),
        QueryType::CDNSKEY => "CDNSKEY".to_string(),
        QueryType::OPENPGPKEY => "OPENPGPKEY".to_string(),
        QueryType::CSYNC => "CSYNC".to_string(),
        QueryType::ZONEMD => "ZONEMD".to_string(),
        QueryType::SVCB => "SVCB".to_string(),
        QueryType::HTTPS => "HTTPS".to_string(),
        QueryType::SPF => "SPF".to_string(),
        QueryType::NID => "NID".to_string(),
        QueryType::L32 => "L32".to_string(),
        QueryType::L64 => "L64".to_string(),
        QueryType::LP => "LP".to_string(),
        QueryType::EUI48 => "EUI48".to_string(),
        QueryType::EUI64 => "EUI64".to_string(),
        QueryType::TKEY => "TKEY".to_string(),
        QueryType::TSIG => "TSIG".to_string(),
        QueryType::IXFR => "IXFR".to_string(),
        QueryType::AXFR => "AXFR".to_string(),
        QueryType::ANY => "ANY".to_string(),
        QueryType::URI => "URI".to_string(),
        QueryType::CAA => "CAA".to_string(),
        QueryType::AVC => "AVC".to_string(),
        QueryType::DOA => "DOA".to_string(),
        QueryType::AMTRELAY => "AMTRELAY".to_string(),
        QueryType::TA => "TA".to_string(),
        QueryType::DLV => "DLV".to_string(),
    }
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
        DnsRecord::TXT {
            domain,
            ttl,
            class,
            data,
            ..
        } => format!(
            "{}\t{}\t{}\tTXT\t{}",
            display_domain(domain),
            ttl,
            display_class(*class),
            data.join(" ")
        ),
        DnsRecord::SOA {
            domain,
            ttl,
            class,
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ..
        } => format!(
            "{}\t{}\t{}\tSOA\t{} {} ( {} {} {} {} {} )",
            display_domain(domain),
            ttl,
            display_class(*class),
            display_domain(mname),
            display_domain(rname),
            serial,
            refresh,
            retry,
            expire,
            minimum
        ),
        DnsRecord::PTR {
            domain,
            ttl,
            class,
            host,
            ..
        } => format!(
            "{}\t{}\t{}\tPTR\t{}",
            display_domain(domain),
            ttl,
            display_class(*class),
            display_domain(host)
        ),
    }
}

fn display_domain(domain: &str) -> String {
    if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{domain}.")
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
