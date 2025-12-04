pub struct BytePacketBuffer {
    pub buffer: [u8; 512],
    pub position: usize,
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buffer: [0; 512],
            position: 0,
        }
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<(), Box<dyn std::error::Error>> {
        self.buffer[pos] = val;

        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), Box<dyn std::error::Error>> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn pos(&self) -> usize {
        self.position
    }

    fn write(&mut self, val: u8) -> Result<(), Box<dyn std::error::Error>> {
        if self.position >= 512 {
            return Err("End of buffer reached".into());
        }

        self.buffer[self.position] = val;
        self.position += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<(), Box<dyn std::error::Error>> {
        self.write(val)
    }

    pub fn write_u16(&mut self, val: u16) -> Result<(), Box<dyn std::error::Error>> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xff) as u8)
    }

    pub fn write_u32(&mut self, val: u32) -> Result<(), Box<dyn std::error::Error>> {
        self.write(((val >> 24) & 0xff) as u8)?;
        self.write(((val >> 16) & 0xff) as u8)?;
        self.write(((val >> 8) & 0xff) as u8)?;
        self.write((val & 0xff) as u8)
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

    pub fn seek(&mut self, pos: usize) {
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

        Ok((first_byte << 24) | (second_byte << 16) | (third_byte << 8) | fourth_byte)
    }

    pub fn write_qname(&mut self, domain: &str) -> Result<(), Box<dyn std::error::Error>> {
        for label in domain.split(".") {
            let len = label.len();

            if len > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;

            for char_byte in label.as_bytes() {
                self.write_u8(*char_byte)?;
            }
        }

        self.write_u8(0)
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
                let offset = (((length_byte as u16) ^ 0xC0) << 8) | (byte_2nd as u16);
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;
                continue;
            } else {
                pos += 1;

                if length_byte == 0 {
                    break;
                }

                out_str.push_str(delimiter);
                let str_buffer = self.get_range(pos, length_byte as usize)?;
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
