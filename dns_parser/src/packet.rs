use crate::{
    buffer::BytePacketBuffer, header::DnsHeader, question::DnsQuestion, record::DnsRecord,
    types::QueryType,
};

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(
        buffer: &mut BytePacketBuffer,
    ) -> Result<DnsPacket, Box<dyn std::error::Error>> {
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

    pub fn write(
        &mut self,
        buffer: &mut BytePacketBuffer,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType};

    #[test]
    fn smoke_test() -> Result<(), Box<dyn std::error::Error>> {
        let qname = "yahoo.com";
        let qtype = QueryType::MX;

        let server = ("8.8.8.8", 53);

        let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

        let mut packet = DnsPacket::new();

        packet.header.id = 6666;
        packet.header.questions = 1;
        packet.header.recursion_desired = true;
        packet
            .questions
            .push(DnsQuestion::new(qname.to_string(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;

        socket.send_to(&req_buffer.buffer[0..req_buffer.pos()], server)?;

        let mut res_buffer = BytePacketBuffer::new();
        socket.recv_from(&mut res_buffer.buffer)?;

        let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
        println!("{:#?}", res_packet.header);

        for q in res_packet.questions {
            println!("{q:#?}");
        }
        for rec in res_packet.answers {
            println!("{rec:#?}");
        }
        for rec in res_packet.authorities {
            println!("{rec:#?}");
        }
        for rec in res_packet.resources {
            println!("{rec:#?}");
        }

        Ok(())
    }
}
