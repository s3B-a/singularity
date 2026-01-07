use super::record::{RecordType, RecordClass, RecordData, DnsRecord};
use std::io::{self, Read, Write, Cursor};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

impl OpCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(OpCode::Query),
            1 => Some(OpCode::IQuery),
            2 => Some(OpCode::Status),
            4 => Some(OpCode::Notify),
            5 => Some(OpCode::Update),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl ResponseCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::NoError,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub opcode: OpCode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHeader {
    pub fn new_query(id: u16, recursion_desired: bool) -> Self {
        Self {
            id,
            is_response: false,
            opcode: OpCode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired,
            recursion_available: false,
            response_code: ResponseCode::NoError,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.id.to_be_bytes())?;
        let mut flags: u16 = 0;
        if self.is_response {
            flags|= 0x8000;
        }

        flags |= ((self.opcode as u16) & 0x0F) << 11;
        if self.authoritative {
            flags |= 1 << 10;
        }

        if self.truncated {
            flags |= 1 << 9;
        }

        if self.recursion_desired {
            flags |= 1 << 8;
        }

        if self.recursion_available {
            flags |= 1 << 7;
        }

        flags |= (self.response_code as u16) & 0x0F;

        writer.write_all(&flags.to_be_bytes())?;
        writer.write_all(&self.question_count.to_be_bytes())?;
        writer.write_all(&self.answer_count.to_be_bytes())?;
        writer.write_all(&self.authority_count.to_be_bytes())?;
        writer.write_all(&self.additional_count.to_be_bytes())?;

        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 12];
        reader.read_exact(&mut buf)?;

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let is_response = (flags & 0x8000) != 0;
        let opcode = OpCode::from_u8(((flags >> 11) & 0x0F) as u8).unwrap_or(OpCode::Query);
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let response_code = ResponseCode::from_u8((flags & 0x000F) as u8);
        let question_count = u16::from_be_bytes([buf[4], buf[5]]);
        let answer_count = u16::from_be_bytes([buf[6], buf[7]]);
        let authority_count = u16::from_be_bytes([buf[8], buf[9]]);
        let additional_count = u16::from_be_bytes([buf[10], buf[11]]);

        Ok(Self {
            id,
            is_response,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            response_code,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: RecordType,
    pub record_class: RecordClass,
}

impl DnsQuestion {
    pub fn new(name: String, record_type: RecordType) -> Self {
        Self {
            name,
            record_type,
            record_class: RecordClass::IN,
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        write_domain_name(writer, &self.name)?;
        writer.write_all(&self.record_type.to_u16().to_be_bytes())?;
        writer.write_all(&self.record_class.to_u16().to_be_bytes())?;
        Ok(())
    }

    pub fn read(reader: &mut Cursor<&[u8]>, packet: &[u8]) -> io::Result<Self> {
        let name = read_domain_name(reader, packet)?;
        
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        
        let record_type = RecordType::from_u16(u16::from_be_bytes([buf[0], buf[1]]));
        let record_class = RecordClass::from_u16(u16::from_be_bytes([buf[2], buf[3]]));

        Ok(Self {
            name,
            record_type,
            record_class,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new_query(id: u16, name: String, record_type: RecordType) -> Self {
        let mut header = DnsHeader::new_query(id, true);
        header.question_count = 1;

        Self {
            header,
            questions: vec![DnsQuestion::new(name, record_type)],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn write(&self) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(512);
        self.header.write(&mut buffer)?;

        for question in &self.questions {
            question.write(&mut buffer)?;
        }

        for answer in &self.answers {
            write_record(&mut buffer, answer)?;
        }

        for auth in &self.authority {
            write_record(&mut buffer, auth)?;
        }

        for add in &self.additional {
            write_record(&mut buffer, add)?;
        }

        Ok(buffer)
    }

    pub fn read(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        let header = DnsHeader::read(&mut cursor)?;

        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            questions.push(DnsQuestion::read(&mut cursor, data)?);
        }

        let mut answers = Vec::new();
        for _ in 0..header.answer_count {
            answers.push(read_record(&mut cursor, data)?);
        }

        let mut authority = Vec::new();
        for _ in 0..header.authority_count {
            authority.push(read_record(&mut cursor, data)?);
        }

        let mut additional = Vec::new();
        for _ in 0..header.additional_count {
            additional.push(read_record(&mut cursor, data)?);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }
}

fn write_domain_name<W: Write>(writer: &mut W, name: &str) -> io::Result<()> {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Label too long"));
        }
        writer.write_all(&[label.len() as u8])?;
        writer.write_all(label.as_bytes())?;
    }
    writer.write_all(&[0u8])?;
    Ok(())
}

fn read_domain_name(reader: &mut Cursor<&[u8]>, packet: &[u8]) -> io::Result<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_position = reader.position();

    loop {
        let current_pos = reader.position() as usize;
        if current_pos >= packet.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Read past end of packet"));
        }

        let len = packet[current_pos];
        reader.set_position(current_pos as u64 + 1);

        if len == 0 {
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if !jumped {
                jump_position = reader.position() + 1;
                jumped = true;
            }

            let next_pos = reader.position() as usize;
            if next_pos >= packet.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid pointer"));
            }

            let offset = (((len & 0x3F) as u16) << 8 | packet[next_pos] as u16) as usize;

            if offset >= packet.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid pointer"));
            }

            reader.set_position(offset as u64);
            continue;
        }

        let pos = reader.position() as usize;
        if pos + len as usize > packet.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Label extends past packet"));
        }

        let label = &packet[pos..pos + len as usize];
        labels.push(String::from_utf8_lossy(label).into_owned());
        reader.set_position((pos + len as usize) as u64);
    }

    if jumped {
        reader.set_position(jump_position);
    }

    Ok(labels.join("."))
}

fn write_record<W: Write>(writer: &mut W, record: &DnsRecord) -> io::Result<()> {
    write_domain_name(writer, &record.name)?;
    writer.write_all(&record.record_type.to_u16().to_be_bytes())?;
    writer.write_all(&record.record_class.to_u16().to_be_bytes())?;
    writer.write_all(&record.ttl.to_be_bytes())?;

    let mut data_buf = Vec::new();
    match &record.data {
        RecordData::A(ip) => data_buf.extend_from_slice(&ip.octets()),
        RecordData::AAAA(ip) => data_buf.extend_from_slice(&ip.octets()),
        RecordData::NS(name) | RecordData::CNAME(name) | RecordData::PTR(name) => {
            write_domain_name(&mut data_buf, name)?;
        }
        RecordData::MX { preference, exchange } => {
            data_buf.extend_from_slice(&preference.to_be_bytes());
            write_domain_name(&mut data_buf, exchange)?;
        }
        RecordData::TXT(texts) => {
            for text in texts {
                if text.len() > 255 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "TXT too long"));
                }
                data_buf.push(text.len() as u8);
                data_buf.extend_from_slice(text.as_bytes());
            }
        }
        RecordData::Unknown(data) => data_buf.extend_from_slice(data),
        _ => {}
    }

    writer.write_all(&(data_buf.len() as u16).to_be_bytes())?;
    writer.write_all(&data_buf)?;

    Ok(())
}

fn read_record(reader: &mut Cursor<&[u8]>, packet: &[u8]) -> io::Result<DnsRecord> {
    let name = read_domain_name(reader, packet)?;

    let mut buf = [0u8; 10];
    reader.read_exact(&mut buf)?;

    let record_type = RecordType::from_u16(u16::from_be_bytes([buf[0], buf[1]]));
    let record_class = RecordClass::from_u16(u16::from_be_bytes([buf[2], buf[3]]));
    let ttl = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let data_len = u16::from_be_bytes([buf[8], buf[9]]) as usize;

    let mut data_buf = vec![0u8; data_len];
    reader.read_exact(&mut data_buf)?;

    let mut data_cursor = Cursor::new(&data_buf[..]);
    let data = match record_type {
        RecordType::A => {
            if data_len != 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid A record"));
            }
            RecordData::A(Ipv4Addr::new(data_buf[0], data_buf[1], data_buf[2], data_buf[3]))
        }
        RecordType::AAAA => {
            if data_len != 16 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid AAAA record"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data_buf);
            RecordData::AAAA(Ipv6Addr::from(octets))
        }
        RecordType::NS | RecordType::CNAME | RecordType::PTR => {
            let target = read_domain_name(&mut data_cursor, packet)?;
            match record_type {
                RecordType::NS => RecordData::NS(target),
                RecordType::CNAME => RecordData::CNAME(target),
                RecordType::PTR => RecordData::PTR(target),
                _ => unreachable!(),
            }
        }
        RecordType::MX => {
            let preference = u16::from_be_bytes([data_buf[0], data_buf[1]]);
            data_cursor.set_position(2);
            let exchange = read_domain_name(&mut data_cursor, packet)?;
            RecordData::MX { preference, exchange }
        }
        RecordType::TXT => {
            let mut texts = Vec::new();
            let mut pos = 0;
            while pos < data_len {
                let txt_len = data_buf[pos] as usize;
                pos += 1;
                if pos + txt_len > data_len {
                    break;
                }
                texts.push(String::from_utf8_lossy(&data_buf[pos..pos + txt_len]).into_owned());
                pos += txt_len;
            }
            RecordData::TXT(texts)
        }
        _ => RecordData::Unknown(data_buf),
    };

    Ok(DnsRecord::new(name, record_type, record_class, ttl, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization() {
        let header = DnsHeader::new_query(1234, true);
        let mut buffer = Vec::new();
        header.write(&mut buffer).unwrap();
        
        let mut cursor = Cursor::new(&buffer[..]);
        let parsed = DnsHeader::read(&mut cursor).unwrap();
        
        assert_eq!(header.id, parsed.id);
        assert_eq!(header.recursion_desired, parsed.recursion_desired);
    }

    #[test]
    fn test_question_serialization() {
        let question = DnsQuestion::new("example.com".to_string(), RecordType::A);
        let mut buffer = Vec::new();
        question.write(&mut buffer).unwrap();
        
        assert!(buffer.len() > 0);
    }

    #[test]
    fn test_packet_creation() {
        let packet = DnsPacket::new_query(5678, "example.com".to_string(), RecordType::A);
        
        assert_eq!(packet.header.id, 5678);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "example.com");
    }
}