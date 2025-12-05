use crate::{buffer::BytePacketBuffer, types::QueryType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(
        &mut self,
        buffer: &mut BytePacketBuffer,
    ) -> Result<(), Box<dyn std::error::Error>> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn std::error::Error>> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::DnsQuestion;
    use crate::{buffer::BytePacketBuffer, types::QueryType};

    #[test]
    fn question_write_and_read_roundtrip() {
        let question = DnsQuestion::new("rust-lang.org".into(), QueryType::MX);
        let mut buffer = BytePacketBuffer::new();
        question.write(&mut buffer).unwrap();
        let written_position = buffer.pos();

        buffer.seek(0);
        let mut parsed = DnsQuestion::new(String::new(), QueryType::UNKNOWN(0));
        parsed.read(&mut buffer).unwrap();

        assert_eq!(question, parsed);
        assert_eq!(written_position, buffer.pos());
    }
}
