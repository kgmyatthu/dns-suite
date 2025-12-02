use std::net::Ipv4Addr;


pub struct BytePacketBuffer {
    buffer: [u8; 512],
    position: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buffer: [0; 512],
            position: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.position
    }

    pub fn read(&mut self) -> Result<u8, Box<dyn std::error::Error>> {
        if self.position >= 512 {
            return Err("End of buffer reached".into());
        }

        let res = self.buffer[self.position];

        self.position += 1;

        Ok(res)
    }

    pub fn get(&self, pos: usize) -> Result<u8, Box<dyn std::error::Error>> {
        if self.position >= 512 {
            return Err("End of buffer reached".into());
        }

        Ok(self.buffer[pos])
    }

    pub fn step(&mut self, steps: usize) {
        self.position += steps;
    }

    pub fn seek(&mut self, pos: usize ) {
        self.position = pos
    }

    pub fn get_range(&self, start: usize, end: usize) -> Result<&[u8], Box<dyn std::error::Error>> {
        let len = start + end;
        if len >= 512 {
            return Err("End of buffer reached".into());
        }
        Ok(&self.buffer[start..len])
    }

    pub fn read_u16(&mut self) -> Result<u16, Box<dyn std::error::Error>> {
        Ok(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    pub fn read_u32(&mut self) -> Result<u32, Box<dyn std::error::Error>> {
        let first_byte = self.read()? as u32;
        let second_byte = self.read()? as u32;
        let third_byte = self.read()? as u32;
        let fourth_byte = self.read()? as u32;

        Ok( (first_byte << 24) | (second_byte << 16) | (third_byte << 8) | (fourth_byte << 0))
    }

    pub fn read_qname(&mut self, out_str: &mut String) -> Result<(), Box<dyn std::error::Error>> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delimiter = "";

        loop {
            if jumps_performed > max_jumps {
                return Err("Name reading jump limit reached".into());
            }
            let length_byte = self.get(pos)?;

            if (length_byte & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2);
                }

                let byte_2nd = self.get(pos + 1)?;
                let offset = (((length_byte as u16) ^ 0xC0) << 8)  | (byte_2nd as u16);
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;
                continue;
            }
            else {
                pos += 1;

                if length_byte == 0{
                    break;
                }

                out_str.push_str(delimiter);
                let str_buffer = self.get_range(pos,length_byte as usize)?;
                out_str.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delimiter = ".";

                pos += length_byte as usize;
            }
        }

        if !jumped {
            self.seek(pos);
        }

        Ok(())
    }

}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn std::error::Error>> {
        self.id = buffer.read_u16()?;

        let a = buffer.read()?;
        let b = buffer.read()?;

        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0f;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0f);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;


        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, PartialOrd, Ord)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn std::error::Error>> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}

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
        ip: std::net::Ipv4Addr
    }
}

impl DnsRecord {
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
                Ok(DnsRecord::A {domain, class, ttl, ip})
            },
            QueryType::UNKNOWN(_) => {

                Ok(DnsRecord::UNKNOWN { domain, qtype, class, ttl, len })
            }

        }

    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket, Box<dyn std::error::Error>> {
        let mut p = DnsPacket::new();

        p.header.read(buffer)?;

        for _ in 0..p.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            p.questions.push(question);
        }

        for _ in 0..p.header.answers {
            p.answers.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..p.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            p.authorities.push(rec);
        }
        for _ in 0..p.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            p.resources.push(rec);
        }

        Ok(p)
    }

}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = std::fs::File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    std::io::Read::read(&mut f, &mut buffer.buffer)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
