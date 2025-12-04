use crate::{buffer::BytePacketBuffer, types::ResultCode};

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

    // 0 0 0 0 0 0 0 1  0 0 1 0 0 0 0 0
    // - -+-+-+- - - -  - -+-+- -+-+-+-
    // Q    O    A T R  R   Z      R
    // R    P    A C D  A          C
    //      C                      O
    //      O                      D
    //      D                      E
    //      E

    pub fn read(
        &mut self,
        buffer: &mut BytePacketBuffer,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn std::error::Error>> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.recursion_available as u8) << 7)
                | ((self.z as u8) << 6)
                | ((self.authed_data as u8) << 5)
                | ((self.checking_disabled as u8) << 4),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)
    }
}

#[cfg(test)]
mod tests {
    use super::DnsHeader;
    use crate::buffer::BytePacketBuffer;
    use crate::types::ResultCode;

    #[test]
    fn header_roundtrip_preserves_flags() {
        let mut header = DnsHeader::new();
        header.id = 0xABCD;
        header.recursion_desired = true;
        header.truncated_message = true;
        header.authoritative_answer = true;
        header.opcode = 2;
        header.response = true;
        header.rescode = ResultCode::SERVFAIL;
        header.checking_disabled = true;
        header.authed_data = true;
        header.z = true;
        header.recursion_available = true;
        header.questions = 3;
        header.answers = 2;
        header.authoritative_entries = 1;
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
    }
}
