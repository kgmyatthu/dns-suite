use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{buffer::BytePacketBuffer, types::QueryType};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: QueryType,
        class: u16,
        ttl: u32,
        data: Vec<u8>,
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
    TXT {
        domain: String,
        class: u16,
        ttl: u32,
        data: Vec<String>,
    }, // 16
    SOA {
        domain: String,
        class: u16,
        ttl: u32,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    }, // 6
    PTR {
        domain: String,
        class: u16,
        host: String,
        ttl: u32,
    }, // 12
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
            QueryType::SOA => {
                let mut mname = String::new();
                buffer.read_qname(&mut mname)?;

                let mut rname = String::new();
                buffer.read_qname(&mut rname)?;

                let serial = buffer.read_u32()?;
                let refresh = buffer.read_u32()?;
                let retry = buffer.read_u32()?;
                let expire = buffer.read_u32()?;
                let minimum = buffer.read_u32()?;

                Ok(DnsRecord::SOA {
                    domain,
                    class,
                    ttl,
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
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
            QueryType::PTR => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::PTR {
                    domain,
                    class,
                    ttl,
                    host,
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
            QueryType::TXT => {
                let mut data = Vec::new();
                let mut bytes_read = 0u16;
                while bytes_read < len {
                    let txt_len = buffer.read()? as u16;
                    bytes_read += 1;
                    if bytes_read + txt_len > len {
                        return Err("TXT record length exceeds rdata".into());
                    }
                    let start = buffer.pos();
                    let txt_bytes = buffer.get_range(start, txt_len as usize)?.to_vec();
                    buffer.step(txt_len as usize);
                    bytes_read += txt_len;
                    data.push(String::from_utf8_lossy(&txt_bytes).to_string());
                }

                Ok(DnsRecord::TXT {
                    domain,
                    class,
                    ttl,
                    data,
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
            _ => {
                let data = buffer.get_range(buffer.pos(), len as usize)?.to_vec();
                buffer.step(len as usize);
                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype,
                    class,
                    ttl,
                    data,
                })
            }
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

                let ip_octets = ip.octets();
                buffer.write_u16(ip_octets.len() as u16)?;

                for octet in ip_octets.iter() {
                    buffer.write_u8(*octet)?;
                }

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
            DnsRecord::SOA {
                domain,
                class,
                ttl,
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                buffer.write_qname(domain.as_str())?;
                buffer.write_u16(QueryType::SOA.to_num())?;
                buffer.write_u16(*class)?;
                buffer.write_u32(*ttl)?;

                let rdlength_pos = buffer.pos();
                buffer.write_u16(0)?;
                let rdata_start = buffer.pos();

                buffer.write_qname(mname)?;
                buffer.write_qname(rname)?;
                buffer.write_u32(*serial)?;
                buffer.write_u32(*refresh)?;
                buffer.write_u32(*retry)?;
                buffer.write_u32(*expire)?;
                buffer.write_u32(*minimum)?;

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
            DnsRecord::PTR {
                domain,
                class,
                host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::PTR.to_num())?;
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
            DnsRecord::TXT {
                domain,
                class,
                ttl,
                data,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::TXT.to_num())?;
                buffer.write_u16(*class)?;
                buffer.write_u32(*ttl)?;

                let rdlength_pos = buffer.pos();
                buffer.write_u16(0)?;
                let rdata_start = buffer.pos();

                for txt in data.iter() {
                    let bytes = txt.as_bytes();
                    buffer.write_u8(bytes.len() as u8)?;
                    for byte in bytes {
                        buffer.write_u8(*byte)?;
                    }
                }

                let rdata_len = (buffer.pos() - rdata_start) as u16;
                buffer.set_u16(rdlength_pos, rdata_len)?;
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
                domain,
                qtype,
                class,
                ttl,
                data,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(qtype.to_num())?;
                buffer.write_u16(*class)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(data.len() as u16)?;

                for byte in data.iter() {
                    buffer.write_u8(*byte)?;
                }

                Ok(buffer.pos() - start_pos)
            }
        }
    }
}
