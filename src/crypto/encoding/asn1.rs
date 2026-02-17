// ASN.1 DER Encoder and Decoder
// https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One

use crate::crypto::{Error, Result};

// Tag Classes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagClass {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3,
}

// Universal Tags
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    Utf8String = 0x0C,
    Sequence = 0x10,
    Set = 0x11,
    PrintableString = 0x13,
    Ia5String = 0x16,
    UtcTime = 0x17,
    GeneralizedTime = 0x18,
}

// DER Encoder
pub struct DerEncoder {
    data: Vec<u8>,
}

// DER Decoder
pub struct DerDecoder<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

// ASN.1 Element
#[derive(Clone, Debug)]
pub struct Asn1Element {
    pub tag: u8,
    pub constructed: bool,
    pub data: Vec<u8>,
}

impl DerEncoder {

    /**
     * Creates a new DER encoder instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: A new DerEncoder instance
     */
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /**
     * Encodes a BOOLEAN value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    value - bool: The boolean value to encode
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn boolean(&mut self, value: bool) -> &mut Self {
        self.write_tag(Tag::Boolean as u8, false);
        self.write_length(1);
        self.data.push(if value { 0xFF } else { 0x00 });

        self
    }

    /**
     * Encodes an INTEGER value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    value - &[u8]: The byte slice representing the integer value
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn integer(&mut self, value: &[u8]) -> &mut Self {
        let mut start = 0;
        while start < value.len() - 1 && value[start] == 0 && value[start + 1] < 0x80 {
            start += 1;
        }

        let trimmed = &value[start..];
        let needs_padding = !trimmed.is_empty() && trimmed[0] >= 0x80;
        self.write_tag(Tag::Integer as u8, false);
        if needs_padding {
            self.write_length(trimmed.len() + 1);
            self.data.push(0x00);
        } else {
            self.write_length(trimmed.len());
        }

        self.data.extend_from_slice(trimmed);

        self
    }

    /**
     * Encodes a u64 INTEGER value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    value - u64: The u64 integer value to encode
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn integer_u64(&mut self, value: u64) -> &mut Self {
        let bytes = value.to_be_bytes();
        
        self.integer(&bytes)
    }

    /**
     * Encodes a BIT STRING value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    bit - &[u8]: The byte slice representing the bit string
     *    unused - u8: The number of unused bits in the last byte
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn bit_string(&mut self, bits: &[u8], unused: u8) -> &mut Self {
        self.write_tag(Tag::BitString as u8, false);
        self.write_length(bits.len() + 1);
        self.data.push(unused);
        self.data.extend_from_slice(bits);
        
        self
    }

    /**
     * Encodes an OCTET STRING value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    value - &[u8]: The byte slice representing the octet string
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn octet_string(&mut self, value: &[u8]) -> &mut Self {
        self.write_tag(Tag::OctetString as u8, false);
        self.write_length(value.len());
        self.data.extend_from_slice(value);

        self
    }

    /**
     * Encodes a NULL value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn null(&mut self) -> &mut Self {
        self.write_tag(Tag::Null as u8, false);
        self.write_length(0);

        self
    }

    /**
     * Encodes an OBJECT IDENTIFIER value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    oid - &[u64]: The slice representing the Object Identifier (OID) components
     * 
     * Returns:
     *    Result<&mut Self>: Mutable reference to the DerEncoder instance or an error if OID is invalid
     */
    pub fn object_identifier(&mut self, oid: &[u64]) -> Result<&mut Self> {
        if oid.len() < 2 {
            return Err(Error::CryptoError("OID must have at least two components".to_string()));
        }

        let mut encoded = Vec::new();
        encoded.push((40 * oid[0] + oid[1]) as u8);
        for &comp in &oid[2..] {
            encode_base128(comp, &mut encoded);
        }

        self.write_tag(Tag::ObjectIdentifier as u8, false);
        self.write_length(encoded.len());
        self.data.extend_from_slice(&encoded);

        Ok(self)
    }

    /**
     * Encodes a UTF8 STRING value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    value - &str: The string value to encode
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn utf8_string(&mut self, value: &str) -> &mut Self {
        self.write_tag(Tag::Utf8String as u8, false);
        self.write_length(value.len());
        self.data.extend_from_slice(value.as_bytes());

        self
    }

    /**
     * Encodes a UTC TIME value
     * Args:
     *    &mut self: Mutable reference to the Derencoder instance
     *    time - &str: The UTC time string in the format "YYMMDDhhmmssZ" to encode
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn utc_time(&mut self, time: &str) -> &mut Self {
        self.write_tag(Tag::UtcTime as u8, false);
        self.write_length(time.len());
        self.data.extend_from_slice(time.as_bytes());

        self
    }

    /**
     * Encodes a PRINTABLE STRING value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    value - &str: The string value to encode
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn printable_string(&mut self, value: &str) -> &mut Self {
        self.write_tag(Tag::PrintableString as u8, false);
        self.write_length(value.len());
        self.data.extend_from_slice(value.as_bytes());

        self
    }

    /**
     * Encodes an IA5 STRING value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    value - &str: The string value to encode
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn ia5_string(&mut self, value: &str) -> &mut Self {
        self.write_tag(Tag::Ia5String as u8, false);
        self.write_length(value.len());
        self.data.extend_from_slice(value.as_bytes());

        self
    }

    /**
     * Encodes a SEQUENCE value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    f - F: A closure that takes a mutable reference to DerEncoder to encode the sequence elements
     * 
     * Returns:
     *    &mut Self where F: FnOnce(&mut DerEncoder): Mutable reference to the DerEncoder instance
     */
    pub fn sequence<F>(&mut self, f: F) -> &mut Self where F: FnOnce(&mut DerEncoder) {
        let mut inner = DerEncoder::new();
        f(&mut inner);

        self.write_tag(Tag::Sequence as u8, true);
        self.write_length(inner.data.len());
        self.data.extend_from_slice(&inner.data);

        self
    }

    /**
     * Encodes a SEQUENCE value without writing the SEQUENCE tag and length (used for raw SEQUENCE content)
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    f - F: A closure that takes a mutable reference to DerEncoder to encode the sequence elements
     * 
     * Returns:
     *    &mut Self where F: FnOnce(&mut DerEncoder): Mutable reference to the DerEncoder instance
     */
    pub fn sequence_raw<F>(&mut self, f: F) -> &mut Self where F: FnOnce(&mut DerEncoder) {
        let mut inner = DerEncoder::new();
        f(&mut inner);
        self.data.extend_from_slice(&inner.data);

        self
    }

    /**
     * Encodes a SET value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    tag_number - u8: The tag number for the SET
     *    f - F: A closure that takes a mutable reference to DerEncoder to encode the set elements
     * 
     * Returns:
     *    &mut Self where F: FnOnce(&mut DerEncoder): Mutable reference to the DerEncoder instance
     */
    pub fn set<F>(&mut self, tag_number: u8, f: F) -> &mut Self where F: FnOnce(&mut DerEncoder) {
        let mut inner = DerEncoder::new();
        f(&mut inner);
        let tag = 0xA0 | tag_number;

        self.write_tag(tag, true);
        self.write_length(inner.data.len());
        self.data.extend_from_slice(&inner.data);

        self
    }

    /**
     * Encodes a CONTEXT-SPECIFIC value
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    tag_num - u8: The context-specific tag number
     *    f - F: A closure that takes a mutable reference to DerEncoder
     *    to encode the context-specific elements
     * 
     * Returns:
     *    &mut Self where F: FnOnce(&mut DerEncoder): Mutable reference to the DerEncoder instance
     */
    pub fn context_specific<F>(&mut self, tag_num: u8, f: F) -> &mut Self where F: FnOnce(&mut DerEncoder) {
        let mut inner = DerEncoder::new();
        f(&mut inner);

        let tag = 0xA0 | tag_num;
        self.write_tag(tag, true);
        self.write_length(inner.data.len());
        self.data.extend_from_slice(&inner.data);

        self
    }

    /**
     * Encodes raw bytes
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    bytes - &[u8]: The byte slice to encode
     * 
     * Returns:
     *    &mut Self: Mutable reference to the DerEncoder instance
     */
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.data.extend_from_slice(bytes);

        self
    }

    /**
     * Finalizes the encoding and returns the encoded byte vector
     * Args:
     *    self: The DerEncoder instance
     * 
     * Returns:
     *    Vec<u8>: The encoded byte vector
     */
    pub fn finish(self) -> Vec<u8> {
        self.data
    }

    /**
     * Writes a tag byte
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    tag - u8: The tag byte to write
     *    constructed - bool: Whether the element is constructed
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn write_tag(&mut self, tag: u8, constructed: bool) {
        let tag_byte = if constructed {
            tag | 0x20
        } else {
            tag
        };

        self.data.push(tag_byte);
    }

    /**
     * Writes a length byte(s)
     * Args:
     *    &mut self: Mutable reference to the DerEncoder instance
     *    length - usize: The length to write
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn write_length(&mut self, length: usize) {
        if length < 128 {
            self.data.push(length as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut len = length;
            while len > 0 {
                len_bytes.push((len & 0xFF) as u8);
                len >>= 8;
            }

            len_bytes.reverse();

            self.data.push(0x80 | len_bytes.len() as u8);
            self.data.extend_from_slice(&len_bytes);
        }
    }
}

impl<'a> DerDecoder<'a>{

    /**
     * Creates a new DerDecoder instance
     * Args:
     *    data - &'a [u8]: The byte slice to decode
     * 
     * Returns:
     *    Self: A new DerDecoder instance
     */
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /**
     * Checks if there are more bytes to read
     * Args:
     *    &self: Reference to the DerDecoder instance
     * 
     * Returns:
     *    bool: True if there are more bytes to be read, false otherwise
     */
    pub fn has_more(&self) -> bool {
        self.pos < self.data.len()
    }

    /**
     * Gets the current position in the data
     * Args:
     *    &self: Reference to the DerDecoder instance
     * 
     * Returns:
     *    usize: The current position in the data
     */
    pub fn get_pos(&self) -> usize {
        self.pos
    }

    /**
     * Peeks at the next tag byte without advancing the position
     * Args:
     *    &self: Reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<u8>: The next tag byte or an error if at the end of data
     */
    pub fn peek_tag(&self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::CryptoError("Unexpected end of data while peeking tag".to_string()));
        }

        Ok(self.data[self.pos])
    }

    /**
     * Reads an ASN.1 element
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<Asn1Element>: The ASN.1 element read or an error if reading fails
     */
    pub fn read_element(&mut self) -> Result<Asn1Element> {
        let tag = self.read_tag()?;
        let constructed = (tag & 0x20) != 0;
        let length = self.read_length()?;
        if self.pos + length > self.data.len() {
            return Err(Error::CryptoError("Unexpected end of data while reading element".to_string()));
        }

        let data = self.data[self.pos..self.pos + length].to_vec();
        self.pos += length;

        Ok(Asn1Element { 
            tag: tag & 0x1F,
            constructed,
            data,
        })
    }

    /**
     * Reads a BOOLEAN value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<bool>: The boolean value read or an error if reading fails
     */
    pub fn boolean(&mut self) -> Result<bool> {
        let element = self.read_element()?;
        if element.tag != Tag::Boolean as u8 || element.data.len() != 1 {
            return Err(Error::CryptoError("Invalid BOOLEAN element".to_string()));
        }

        if element.data.len() != 1 {
            return Err(Error::CryptoError("Invalid BOOLEAN length".to_string()));
        }

        Ok(element.data[0] != 0)
    }

    /**
     * Reads an INTEGER value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<Vec<u8>>: The byte vector representing the integer value or an error if reading fails
     */
    pub fn integer(&mut self) -> Result<Vec<u8>> {
        let element = self.read_element()?;
        if element.tag != Tag::Integer as u8 {
            return Err(Error::CryptoError("Invalid INTEGER element".to_string()));
        }

        if element.data.len() > 1 && element.data[0] == 0 && element.data[1] < 0x80 {
            Ok(element.data[1..].to_vec())
        } else {
            Ok(element.data)
        }
    }

    /**
     * Reads a u64 INTEGER value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<u64>: The u64 integer value read or an error if reading fails
     *    or if the integer is too large
     */
    pub fn integer_u64(&mut self) -> Result<u64> {
        let int_bytes = self.integer()?;
        if int_bytes.len() > 8 {
            return Err(Error::CryptoError("INTEGER too large to fit in u64".to_string()));
        }

        let mut value = 0u64;
        for &byte in &int_bytes {
            value = (value << 8) | (byte as u64);
        }

        Ok(value)
    }

    /**
     * Reads a BIT STRING value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<(Vec<u8>, u8)>: A tuple containing the byte vector representing the bit string
     *    and the number of unused bits in the last byte, or an error if reading fails
     */
    pub fn bit_string(&mut self) -> Result<(Vec<u8>, u8)> {
        let element = self.read_element()?;
        if element.tag != Tag::BitString as u8 {
            return Err(Error::CryptoError("Invalid BIT STRING element".to_string()));
        }

        if element.data.is_empty() {
            return Err(Error::CryptoError("Invalid BIT STRING length".to_string()));
        }

        let unused = element.data[0];
        let bits = element.data[1..].to_vec();

        Ok((bits, unused))
    }

    /**
     * Reads an OCTET STRING value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<Vec<u8>>: The byte vector representing the octet string or an error if reading fails
     */
    pub fn octet_string(&mut self) -> Result<Vec<u8>> {
        let element = self.read_element()?;
        if element.tag != Tag::OctetString as u8 {
            return Err(Error::CryptoError("Invalid OCTET STRING element".to_string()));
        }

        Ok(element.data)
    }

    /**
     * Reads a NULL value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<()>: Ok if NULL is read successfully or an error if reading fails
     */
    pub fn null(&mut self) -> Result<()> {
        let element = self.read_element()?;
        if element.tag != Tag::Null as u8 {
            return Err(Error::CryptoError("Invalid NULL element".to_string()));
        }

        if !element.data.is_empty() {
            return Err(Error::CryptoError("Invalid NULL length".to_string()));
        }

        Ok(())
    }

    /**
     * Reads an OBJECT IDENTIFIER value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<Vec<u64>>: The vector representing the Object Identifier (OID) components
     *    or an error if reading fails
     */
    pub fn object_identifier(&mut self) -> Result<Vec<u64>> {
        let element = self.read_element()?;
        if element.tag != Tag::ObjectIdentifier as u8 {
            return Err(Error::CryptoError("Invalid OBJECT IDENTIFIER element".to_string()));
        }

        if element.data.is_empty() {
            return Err(Error::CryptoError("Invalid OBJECT IDENTIFIER length".to_string()));
        }

        let mut oid = Vec::new();
        let first_byte = element.data[0] as u64;

        oid.push(first_byte / 40);
        oid.push(first_byte % 40);
        let mut i = 1;
        while i < element.data.len() {
            let (value, consumed) = decode_base128(&element.data[i..])?;
            oid.push(value);
            i += consumed;
        }

        Ok(oid)
    }

    /**
     * Reads a UTF8 STRING value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<String>: The string value read or an error if reading fails
     */
    pub fn utf8_string(&mut self) -> Result<String> {
        let element = self.read_element()?;
        if element.tag != Tag::Utf8String as u8 {
            return Err(Error::CryptoError("Invalid UTF8 STRING element".to_string()));
        }

        String::from_utf8(element.data).map_err(|_| Error::CryptoError("Invalid UTF-8".to_string()))
    }

    /**
     * Reads a UTC TIME value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<String>: The string value read or an error if reading fails
     */
    pub fn utc_time(&mut self) -> Result<String> {
        let element = self.read_element()?;
        if element.tag != Tag::UtcTime as u8 {
            return Err(Error::CryptoError("Invalid UTC TIME element".to_string()));
        }

        String::from_utf8(element.data).map_err(|_| Error::CryptoError("Invalid UTC TIME".to_string()))
    }

    /**
     * Reads a PRINTABLE STRING value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<String>: The string value read or an error if reading fails
     */
    pub fn printable_string(&mut self) -> Result<String> {
        let element = self.read_element()?;
        if element.tag != Tag::PrintableString as u8 {
            return Err(Error::CryptoError("Invalid PRINTABLE STRING element".to_string()));
        }

        String::from_utf8(element.data).map_err(|_| Error::CryptoError("Invalid PRINTABLE STRING".to_string()))
    }

    /**
     * Reads an IA5 STRING value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<String>: The string value read or an error if reading fails
     */
    pub fn ia5_string(&mut self) -> Result<String> {
        let element = self.read_element()?;
        if element.tag != Tag::Ia5String as u8 {
            return Err(Error::CryptoError("Invalid IA5 STRING element".to_string()));
        }

        String::from_utf8(element.data).map_err(|_| Error::CryptoError("Invalid IA5 STRING".to_string()))
    }

    /**
     * Reads a SEQUENCE value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instnace
     *    f - F: A closure that takes a mutable reference to DerDecoder to decode the sequence elements
     * 
     * Returns:
     *    Result<T> where F: FnOnce(&mut DerDecoder) -> Result<T>: The result of the closure or an error
     *    if reading fails
     */
    pub fn sequence<F, T>(&mut self, f: F) -> Result<T> where F: FnOnce(&mut DerDecoder) -> Result<T> {
        let element = self.read_element()?;
        if element.tag != Tag::Sequence as u8 || !element.constructed {
            return Err(Error::CryptoError("Invalid SEQUENCE element".to_string()));
        }

        let mut inner = DerDecoder::new(&element.data);
        f(&mut inner)
    }

    /**
     * Reads a SEQUENCE value without expecting the SEQUENCE tag and length (used for raw SEQUENCE content)
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     *    f - F: A closure that takes a mutable reference to DerDecoder to decode the sequence elements
     * 
     * Returns:
     *    Result<T> where F: FnOnce(&mut DerDecoder) -> Result<T>: The result of the closure or an error
     *    if reading fails
     */
    pub fn sequence_raw<F, T>(&mut self, f: F) -> Result<T> where F: FnOnce(&mut DerDecoder) -> Result<T> {
        let element = self.read_element()?;
        if !element.constructed {
            return Err(Error::CryptoError("Expected constructed SEQUENCE content".to_string()));
        }

        let mut inner = DerDecoder::new(&element.data);
        f(&mut inner)
    }

    /**
     * Reads a SET value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     *    f - F: A closure that takes a mutable reference to DerDecoder to decode the set elements
     * 
     * Returns:
     *    Result<T> where F: FnOnce(&mut DerDecoder) -> Result<T>: The result of the closure or an error
     *    if reading fails
     */
    pub fn set<F, T>(&mut self, f: F) -> Result<T> where F: FnOnce(&mut DerDecoder) -> Result<T> {
        let element = self.read_element()?;
        if element.tag != Tag::Set as u8 || !element.constructed {
            return Err(Error::CryptoError("Invalid SET element".to_string()));
        }

        let mut inner = DerDecoder::new(&element.data);
        f(&mut inner)
    }

    /**
     * Reads a CONTEXT-SPECIFIC value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     *    expected_tag - u8: The expected context-specific tag number
     *    f - F: A closure that takes a mutable reference to DerDecoder to decode
     *    the context-specific elements
     * 
     * Returns:
     *    Result<T> where F: FnOnce(&mut DerDecoder) -> Result<T>: The result of the closure or an error
     *    if reading fails
     */
    pub fn context_specific<F, T>(&mut self, expected_tag: u8, f: F) -> Result<T> where F: FnOnce(&mut DerDecoder) -> Result<T> {
        let tag = self.read_tag()?;
        let tag_num = tag & 0x1F;
        if (tag & 0xC0) != 0x80 || tag_num != expected_tag {
            return Err(Error::CryptoError(format!("Expected context-specific tag [{}]", expected_tag)));
        }

        let length = self.read_length()?;
        if self.pos + length > self.data.len() {
            return Err(Error::CryptoError("Unexpected end of data in context-specific element".to_string()));
        }

        let data = &self.data[self.pos..self.pos + length];
        self.pos += length;

        let mut inner = DerDecoder::new(data);
        f(&mut inner)
    }

    /**
     * Reads an optional CONTEXT-SPECIFIC value
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     *    expected_tag - u8: The expected context-specific tag number
     *    f - F: A closure that takes a mutable reference to DerDecoder to decode
     *    the context-specific elements
     * 
     * Returns:
     *    Result<Option<T>> where F: FnOnce(&mut DerDecoder) -> Result<T>: An optional result of the closure
     *    or None if the expected tag is not present
     */
    pub fn optional_context_specific<F, T>(&mut self, expected_tag: u8, f: F) -> Result<Option<T>> where F: FnOnce(&mut DerDecoder) -> Result<T> {
        if !self.has_more() {
            return Ok(None);
        }

        let tag = self.peek_tag()?;
        let tag_num = tag & 0x1F;
        if (tag & 0xC0) == 0x80 && tag_num == expected_tag {
            self.context_specific(expected_tag, f).map(Some)
        } else {
            Ok(None)
        }
    }

    /**
     * Reads raw bytes
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     *    length - usize: The number of bytes to read
     * 
     * Returns:
     *    Result<Vec<u8>>: The byte vector read or an error if reading fails
     */
    pub fn read_bytes(&mut self, length: usize) -> Result<Vec<u8>> {
        if self.pos + length > self.data.len() {
            return Err(Error::CryptoError("Unexpected end of data while reading bytes".to_string()));
        }

        let bytes = self.data[self.pos..self.pos + length].to_vec();
        self.pos += length;

        Ok(bytes)
    }

    /**
     * Reads a tag byte
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<u8>: The tag byte read or an error if reading fails
     */
    fn read_tag(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::CryptoError("Unexpected end of data while reading tag".to_string()));
        }

        let tag = self.data[self.pos];
        self.pos += 1;

        Ok(tag)
    }

    /**
     * Reads a length byte(s)
     * Args:
     *    &mut self: Mutable reference to the DerDecoder instance
     * 
     * Returns:
     *    Result<usize>: The length read or an error if reading fails
     */
    fn read_length(&mut self) -> Result<usize> {
        if self.pos >= self.data.len() {
            return Err(Error::CryptoError("Unexpected end of data while reading length".to_string()));
        }

        let first_byte = self.data[self.pos];
        self.pos += 1;
        if first_byte < 128 {
            Ok(first_byte as usize)
        } else {
            let num_bytes = (first_byte & 0x7F) as usize;
            if num_bytes > 4 {
                return Err(Error::CryptoError("Length too large".to_string()));
            }

            if self.pos + num_bytes > self.data.len() {
                return Err(Error::CryptoError("Unexpected end of data while reading length".to_string()));
            }

            let mut length = 0usize;
            for _ in 0..num_bytes {
                length = (length << 8) | (self.data[self.pos] as usize);
                self.pos += 1;
            }

            Ok(length)
        }
    }
}

// Default implementation for DerEncoder
impl Default for DerEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// Default implementation for DerDecoder
impl Default for DerDecoder<'_> {
    fn default() -> Self {
        Self::new(&[])
    }
}

/**
 * Encodes a u64 value using base-128 encoding
 * Args:
 *    mut value - u64: The u64 value to encode
 *    output - &mut Vec<u8>: The output byte vector to store the encoded value
 * 
 * Returns:
 *    (): Nothing
 */
fn encode_base128(mut value: u64, output: &mut Vec<u8>) {
    if value == 0 {
        output.push(0);
        return;
    }

    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0x7F) as u8);
        value >>= 7;
    }

    bytes.reverse();
    for (i, &byte) in bytes.iter().enumerate() {
        if i < bytes.len() - 1 {
            output.push(byte | 0x80);
        } else {
            output.push(byte);
        }
    }
}

/**
 * Decodes a base-128 encoded u64 value
 * Args:
 *    data - &[u8]: The byte slice containing the base-128 encoded value
 * 
 * Returns:
 *    Result<(u64, usize)>: A tuple containing the decoded u64 value and the number of bytes consumed,
 *    or an error if decoding fails
 */
fn decode_base128(data: &[u8]) -> Result<(u64, usize)> {
    let mut value = 0u64;
    let mut consumed = 0;
    for & byte in data {
        consumed += 1;
        value = (value << 7) | ((byte & 0x7F) as u64);
        if (byte & 0x80) == 0 {
            return Ok((value, consumed));
        }

        if consumed > 9 {
            return Err(Error::CryptoError("Base128 integer too large".to_string()));
        }
    }

    Err(Error::CryptoError("Incomplete base128 integer".to_string()))
}

// Commonly used OIDs rexported as constants
pub mod oid {
    pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    pub const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
    pub const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
    pub const SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
    pub const ED25519: &[u64] = &[1, 3, 101, 112];
    pub const X25519: &[u64] = &[1, 3, 101, 110];
    pub const SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_boolean() {
        let mut encoder = DerEncoder::new();
        encoder.boolean(true);
        let encoded = encoder.finish();
        
        let mut decoder = DerDecoder::new(&encoded);
        assert_eq!(decoder.boolean().unwrap(), true);
    }

    #[test]
    fn test_encode_decode_integer() {
        let mut encoder = DerEncoder::new();
        encoder.integer_u64(12345);
        let encoded = encoder.finish();
        
        let mut decoder = DerDecoder::new(&encoded);
        assert_eq!(decoder.integer_u64().unwrap(), 12345);
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let data = b"Hello, World!";
        let mut encoder = DerEncoder::new();
        encoder.octet_string(data);
        let encoded = encoder.finish();
        
        let mut decoder = DerDecoder::new(&encoded);
        assert_eq!(decoder.octet_string().unwrap(), data);
    }

    #[test]
    fn test_encode_decode_null() {
        let mut encoder = DerEncoder::new();
        encoder.null();
        let encoded = encoder.finish();
        
        let mut decoder = DerDecoder::new(&encoded);
        assert!(decoder.null().is_ok());
    }

    #[test]
    fn test_encode_decode_oid() {
        let oid: Vec<u64> = vec![1, 2, 840, 113549, 1, 1, 1];
        let mut encoder = DerEncoder::new();
        encoder.object_identifier(&oid).unwrap();
        let encoded = encoder.finish();
        
        let mut decoder = DerDecoder::new(&encoded);
        assert_eq!(decoder.object_identifier().unwrap(), oid);
    }

    #[test]
    fn test_encode_decode_sequence() {
        let mut encoder = DerEncoder::new();
        encoder.sequence(|seq| {
            seq.integer_u64(42);
            seq.octet_string(b"test");
        });
        let encoded = encoder.finish();
        
        let mut decoder = DerDecoder::new(&encoded);
        decoder.sequence(|seq| {
            assert_eq!(seq.integer_u64().unwrap(), 42);
            assert_eq!(seq.octet_string().unwrap(), b"test");
            Ok(())
        }).unwrap();
    }

    #[test]
    fn test_encode_decode_context_specific() {
        let mut encoder = DerEncoder::new();
        encoder.context_specific(0, |ctx| {
            ctx.integer_u64(99);
        });
        let encoded = encoder.finish();
        
        let mut decoder = DerDecoder::new(&encoded);
        decoder.context_specific(0, |ctx| {
            assert_eq!(ctx.integer_u64().unwrap(), 99);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn test_rsa_oid() {
        let mut encoder = DerEncoder::new();
        encoder.object_identifier(oid::RSA_ENCRYPTION).unwrap();
        let encoded = encoder.finish();
        
        let mut decoder = DerDecoder::new(&encoded);
        assert_eq!(decoder.object_identifier().unwrap(), oid::RSA_ENCRYPTION);
    }
}