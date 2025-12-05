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
    use super::DnsPacket;
    use crate::{
        buffer::BytePacketBuffer,
        question::DnsQuestion,
        record::DnsRecord,
        types::{QueryType, ResultCode},
    };
    use std::net::Ipv4Addr;

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
}
