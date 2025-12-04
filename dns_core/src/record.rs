use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{buffer::BytePacketBuffer, types::QueryType};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
    },
    A {
        domain: String,
        class: u16,
        ttl: u32,
        addr: std::net::Ipv4Addr,
    },
    NS {
        domain: String,
        class: u16,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        class: u16,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        class: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        class: u16,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    //       name     type   class         ttl        len      ip
    //       ------  ------  ------  --------------  ------  --------------
    // HEX   c0  0c  00  01  00  01  00  00  01  25  00  04  d8  3a  d3  8e
    // DEC   192 12    1       1           293         4     216 58  211 142

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, Box<dyn std::error::Error>> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype = QueryType::from_num(buffer.read_u16()?);
        let class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let ip_byte = buffer.read_u32()?;
                let ip = Ipv4Addr::new(
                    ((ip_byte >> 24) & 0xff) as u8,
                    ((ip_byte >> 16) & 0xff) as u8,
                    ((ip_byte >> 8) & 0xff) as u8,
                    ((ip_byte >> 0) & 0xff) as u8,
                );
                Ok(DnsRecord::A {
                    domain,
                    class,
                    ttl,
                    addr: ip,
                })
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::NS {
                    domain,
                    host,
                    ttl,
                    class,
                })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host,
                    ttl,
                    class,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                    class,
                })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain,
                    addr,
                    ttl,
                    class,
                })
            }
            QueryType::UNKNOWN(_) => Ok(DnsRecord::UNKNOWN {
                domain,
                qtype,
                class,
                ttl,
                len,
            }),
        }
    }

    pub fn write(
        &self,
        buffer: &mut BytePacketBuffer,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let start_pos = buffer.pos();
        match self {
            DnsRecord::A {
                domain,
                class,
                ttl,
                addr: ip,
            } => {
                buffer.write_qname(domain.as_str())?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(*class)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(4)?;

                let ip_octets = ip.octets();
                buffer.write_u8(ip_octets[0])?;
                buffer.write_u8(ip_octets[1])?;
                buffer.write_u8(ip_octets[2])?;
                buffer.write_u8(ip_octets[3])?;

                Ok(buffer.pos() - start_pos)
            }
            DnsRecord::NS {
                domain,
                class,
                host,
                ttl,
            } => {
                buffer.write_qname(domain.as_str())?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(*class)?;
                buffer.write_u32(*ttl)?;

                let rdlength_pos = buffer.pos();
                buffer.write_u16(0)?;

                let rdata_start = buffer.pos();

                buffer.write_qname(host)?;

                let rdata_len = (buffer.pos() - rdata_start) as u16;

                buffer.set_u16(rdlength_pos, rdata_len)?;

                Ok(buffer.pos() - start_pos)
            }
            DnsRecord::CNAME {
                domain,
                host,
                class,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(*class)?;
                buffer.write_u32(*ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
                Ok(buffer.pos() - start_pos)
            }
            DnsRecord::MX {
                domain,
                class,
                priority,
                host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(*class)?;
                buffer.write_u32(*ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(*priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
                Ok(buffer.pos() - start_pos)
            }
            DnsRecord::AAAA {
                domain,
                addr,
                class,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(*class)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
                Ok(buffer.pos() - start_pos)
            }
            DnsRecord::UNKNOWN {
                domain: _,
                qtype: _,
                class: _,
                ttl: _,
                len: _,
            } => {
                println!("Unkown Record Type!");
                Ok(0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DnsRecord;
    use crate::buffer::BytePacketBuffer;
    use crate::types::QueryType;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_record_roundtrip() {
        let mut buffer = BytePacketBuffer::new();
        let record = DnsRecord::A {
            domain: "example.com".to_string(),
            class: 1,
            ttl: 3600,
            addr: Ipv4Addr::new(127, 0, 0, 1),
        };

        record.write(&mut buffer).unwrap();
        buffer.seek(0);

        let parsed = DnsRecord::read(&mut buffer).unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn cname_and_mx_records_report_length() {
        let mut cname_buffer = BytePacketBuffer::new();
        let cname = DnsRecord::CNAME {
            domain: "alias.example".into(),
            class: 1,
            host: "target.example".into(),
            ttl: 123,
        };

        let cname_len = cname.write(&mut cname_buffer).unwrap();
        assert!(cname_len > 0);

        cname_buffer.seek(0);
        let parsed_cname = DnsRecord::read(&mut cname_buffer).unwrap();
        assert_eq!(cname, parsed_cname);

        let mut mx_buffer = BytePacketBuffer::new();
        let mx = DnsRecord::MX {
            domain: "mx.example".into(),
            priority: 10,
            class: 1,
            host: "mail.example".into(),
            ttl: 55,
        };

        let mx_len = mx.write(&mut mx_buffer).unwrap();
        assert!(mx_len > 0);

        mx_buffer.seek(0);
        let parsed_mx = DnsRecord::read(&mut mx_buffer).unwrap();
        assert_eq!(mx, parsed_mx);
    }

    #[test]
    fn unknown_record_preserves_type() {
        let mut buffer = BytePacketBuffer::new();

        buffer.write_qname("unknown.example").unwrap();
        buffer.write_u16(65000).unwrap();
        buffer.write_u16(1).unwrap();
        buffer.write_u32(0).unwrap();
        buffer.write_u16(0).unwrap();
        buffer.seek(0);

        let parsed = DnsRecord::read(&mut buffer).unwrap();
        assert_eq!(
            parsed,
            DnsRecord::UNKNOWN {
                domain: "unknown.example".into(),
                qtype: QueryType::UNKNOWN(65000),
                class: 1,
                ttl: 0,
                len: 0,
            }
        );
    }

    #[test]
    fn aaaa_record_roundtrip() {
        let mut buffer = BytePacketBuffer::new();
        let record = DnsRecord::AAAA {
            domain: "ipv6.example".into(),
            addr: Ipv6Addr::LOCALHOST,
            class: 1,
            ttl: 600,
        };

        record.write(&mut buffer).unwrap();
        buffer.seek(0);

        let parsed = DnsRecord::read(&mut buffer).unwrap();
        assert_eq!(record, parsed);
    }
}
