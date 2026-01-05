//! Separate generic TLV parser
pub struct TlvEntry {
    pub tlv_type: u8,
    pub value: Vec<u8>,
}

pub struct TlvParser<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> TlvParser<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    pub fn parse_next(&mut self) -> Option<TlvEntry> {
        if self.position + 2 >= self.buffer.len() {
            return None; // Not enough bytes for T and L
        }

        let tlv_type = self.buffer[self.position];
        let length = self.buffer[self.position + 1];
        self.position += 2;

        if self.position + length as usize > self.buffer.len() {
            return None; // Not enough bytes for V
        }

        let value = self.buffer[self.position..self.position + length as usize].to_vec();
        self.position += length as usize;

        Some(TlvEntry { tlv_type, value })
    }

    pub fn parse_all(&mut self) -> Vec<TlvEntry> {
        let mut entries = Vec::new();
        while let Some(entry) = self.parse_next() {
            entries.push(entry);
        }
        entries
    }
}
