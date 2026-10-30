use std::fmt;

pub const MAX_RANGES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePart {
    pub content_range: ContentRange,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteRangeSpec {
    FromTo(u64, u64),
    From(u64),
    Suffix(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    UnsupportedUnit,
    Invalid,
    TooManyRanges,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeOutcome {
    Partial(Vec<ByteRange>),
    NotSatisfiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRange {
    Bytes { range: ByteRange, complete_length: Option<u64> },
    Unsatisfied { complete_length: u64 },
}

impl ByteRangeSpec {
    pub fn resolve(&self, len: u64) -> Option<ByteRange> {
        match *self {
            ByteRangeSpec::FromTo(first, last) if first < len => Some(ByteRange { start: first, end: last.min(len - 1) }),
            ByteRangeSpec::From(first) if first < len => Some(ByteRange { start: first, end: len - 1 }),
            ByteRangeSpec::Suffix(length) if length > 0 && len > 0 => Some(ByteRange { start: len - length.min(len), end: len - 1 }),
            _ => None,
        }
    }
}

impl ByteRange {
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    pub fn slice<'a>(&self, content: &'a [u8]) -> &'a [u8] {
        &content[self.start as usize..=self.end as usize]
    }
}

impl ContentRange {
    pub fn parse(value: &str) -> Option<Self> {
        let rest = value.trim();
        let (unit, rest) = rest.split_once(' ')?;
        if !unit.eq_ignore_ascii_case("bytes") {
            return None;
        }

        let (range, complete) = rest.trim().split_once('/')?;
        let complete_length = match complete.trim() {
            "*" => None,
            digits => Some(parse_digits(digits).ok()?),
        };

        if range.trim() == "*" {
            return complete_length.map(|complete_length| ContentRange::Unsatisfied { complete_length });
        }

        let (first, last) = range.trim().split_once('-')?;
        let (start, end) = (parse_digits(first).ok()?, parse_digits(last).ok()?);
        if end < start || complete_length.map(|c| end >= c).unwrap_or(false) {
            return None;
        }

        Some(ContentRange::Bytes { range: ByteRange { start, end }, complete_length })
    }
}

fn parse_digits(value: &str) -> Result<u64, RangeError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RangeError::Invalid);
    }

    value.parse().map_err(|_| RangeError::Invalid)
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

pub fn parse_range_header(value: &str) -> Result<Vec<ByteRangeSpec>, RangeError> {
    let (unit, set) = value.trim().split_once('=').ok_or(RangeError::Invalid)?;
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return Err(RangeError::UnsupportedUnit);
    }

    let mut specs = Vec::new();
    for element in set.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (first, last) = element.split_once('-').ok_or(RangeError::Invalid)?;
        let spec = match (first.trim(), last.trim()) {
            ("", "") => return Err(RangeError::Invalid),
            ("", suffix) => ByteRangeSpec::Suffix(parse_digits(suffix)?),
            (first, "") => ByteRangeSpec::From(parse_digits(first)?),
            (first, last) => {
                let (first, last) = (parse_digits(first)?, parse_digits(last)?);
                if last < first {
                    return Err(RangeError::Invalid);
                }

                ByteRangeSpec::FromTo(first, last)
            }
        };

        specs.push(spec);
        if specs.len() > MAX_RANGES {
            return Err(RangeError::TooManyRanges);
        }
    }

    if specs.is_empty() {
        Err(RangeError::Invalid)
    } else {
        Ok(specs)
    }
}

pub fn format_range_header(specs: &[ByteRangeSpec]) -> String {
    let set: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
    format!("bytes={}", set.join(","))
}

pub fn evaluate_ranges(specs: &[ByteRangeSpec], len: u64) -> RangeOutcome {
    let mut ranges: Vec<ByteRange> = specs.iter().filter_map(|s| s.resolve(len)).collect();
    if ranges.is_empty() {
        return RangeOutcome::NotSatisfiable;
    }

    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<ByteRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end.saturating_add(1) => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }

    RangeOutcome::Partial(merged)
}

pub fn build_multipart_byteranges(content: &[u8], ranges: &[ByteRange], content_type: Option<&str>, boundary: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for range in ranges {
        body.extend_from_slice(format!("\r\n--{}\r\n", boundary).as_bytes());
        if let Some(content_type) = content_type {
            body.extend_from_slice(format!("Content-Type: {}\r\n", content_type).as_bytes());
        }

        let content_range = ContentRange::Bytes { range: *range, complete_length: Some(content.len() as u64) };
        body.extend_from_slice(format!("Content-Range: {}\r\n\r\n", content_range).as_bytes());
        body.extend_from_slice(range.slice(content));
    }

    body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
    body
}

pub fn parse_multipart_byteranges(body: &[u8], boundary: &str) -> Result<Vec<BytePart>, String> {
    let delimiter = format!("--{}", boundary).into_bytes();
    let mut pos = find(body, &delimiter, 0).ok_or("multipart/byteranges body has no boundary")?;
    let mut parts = Vec::new();
    loop {
        pos += delimiter.len();
        if body[pos..].starts_with(b"--") {
            return Ok(parts);
        }

        pos = find(body, b"\r\n", pos).ok_or("unterminated multipart boundary line")? + 2;
        let headers_end = find(body, b"\r\n\r\n", pos).ok_or("unterminated multipart part headers")?;
        let header_text = std::str::from_utf8(&body[pos..headers_end]).map_err(|_| "multipart part headers are not UTF-8")?;

        let mut content_range = None;
        let mut content_type = None;
        for line in header_text.split("\r\n") {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-range") {
                    content_range = ContentRange::parse(value);
                } else if name.trim().eq_ignore_ascii_case("content-type") {
                    content_type = Some(value.trim().to_string());
                }
            }
        }

        let (range, content_range) = match content_range {
            Some(cr @ ContentRange::Bytes { range, .. }) => (range, cr),
            _ => return Err("multipart part is missing a valid Content-Range".to_string()),
        };

        let data_start = headers_end + 4;
        let data_end = data_start.checked_add(range.len() as usize).filter(|&end| end <= body.len()).ok_or("multipart part is truncated")?;
        parts.push(BytePart { content_range, content_type, data: body[data_start..data_end].to_vec() });

        pos = data_end;
        if !body[pos..].starts_with(b"\r\n") || !body[pos + 2..].starts_with(&delimiter) {
            return Err("multipart part is not followed by a boundary".to_string());
        }

        pos += 2;
    }
}

impl fmt::Display for ByteRangeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ByteRangeSpec::FromTo(first, last) => write!(f, "{}-{}", first, last),
            ByteRangeSpec::From(first) => write!(f, "{}-", first),
            ByteRangeSpec::Suffix(length) => write!(f, "-{}", length),
        }
    }
}

impl fmt::Display for ContentRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentRange::Bytes { range, complete_length: Some(len) } => write!(f, "bytes {}-{}/{}", range.start, range.end, len),
            ContentRange::Bytes { range, complete_length: None } => write!(f, "bytes {}-{}/*", range.start, range.end),
            ContentRange::Unsatisfied { complete_length } => write!(f, "bytes */{}", complete_length),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_range_header_forms() {
        assert_eq!(parse_range_header("bytes=0-499"), Ok(vec![ByteRangeSpec::FromTo(0, 499)]));
        assert_eq!(
            parse_range_header("Bytes = 500-, -200 ,, 9-9"),
            Ok(vec![ByteRangeSpec::From(500), ByteRangeSpec::Suffix(200), ByteRangeSpec::FromTo(9, 9)])
        );
        assert_eq!(parse_range_header("items=0-1"), Err(RangeError::UnsupportedUnit));
        for invalid in ["bytes=", "bytes=-", "bytes=5-1", "bytes=a-b", "bytes=+1-2", "0-1", "bytes=1-2-3"] {
            assert_eq!(parse_range_header(invalid), Err(RangeError::Invalid), "{}", invalid);
        }
    }

    #[test]
    fn test_parse_range_header_caps_range_count() {
        let many = format!("bytes={}", (0..=MAX_RANGES).map(|i| format!("{}-{}", i, i)).collect::<Vec<_>>().join(","));
        assert_eq!(parse_range_header(&many), Err(RangeError::TooManyRanges));
    }

    #[test]
    fn test_resolve_specs_against_length() {
        assert_eq!(ByteRangeSpec::FromTo(0, 9999).resolve(100), Some(ByteRange { start: 0, end: 99 }));
        assert_eq!(ByteRangeSpec::From(100).resolve(100), None);
        assert_eq!(ByteRangeSpec::Suffix(500).resolve(100), Some(ByteRange { start: 0, end: 99 }));
        assert_eq!(ByteRangeSpec::Suffix(10).resolve(100), Some(ByteRange { start: 90, end: 99 }));
        assert_eq!(ByteRangeSpec::Suffix(0).resolve(100), None);
        assert_eq!(ByteRangeSpec::From(0).resolve(0), None);
    }

    #[test]
    fn test_evaluate_merges_overlapping_ranges() {
        let specs = parse_range_header("bytes=50-59, 0-9, 5-14, 15-19").unwrap();
        assert_eq!(
            evaluate_ranges(&specs, 100),
            RangeOutcome::Partial(vec![ByteRange { start: 0, end: 19 }, ByteRange { start: 50, end: 59 }])
        );
        assert_eq!(evaluate_ranges(&parse_range_header("bytes=200-").unwrap(), 100), RangeOutcome::NotSatisfiable);
    }

    #[test]
    fn test_content_range_roundtrip() {
        for value in ["bytes 0-499/1234", "bytes 500-999/*", "bytes */1234"] {
            assert_eq!(ContentRange::parse(value).unwrap().to_string(), value);
        }

        assert_eq!(ContentRange::parse("bytes 5-1/10"), None);
        assert_eq!(ContentRange::parse("bytes 0-10/10"), None);
        assert_eq!(ContentRange::parse("items 0-1/2"), None);
    }

    #[test]
    fn test_multipart_byteranges_roundtrip_with_boundary_in_data() {
        let content = b"0123456789--BOUNDARY\r\n--BOUNDARY-- tail".to_vec();
        let ranges = [ByteRange { start: 0, end: 3 }, ByteRange { start: 10, end: 29 }];
        let body = build_multipart_byteranges(&content, &ranges, Some("text/plain"), "BOUNDARY");

        let parts = parse_multipart_byteranges(&body, "BOUNDARY").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].data, b"0123");
        assert_eq!(parts[0].content_type.as_deref(), Some("text/plain"));
        assert_eq!(parts[1].data, &content[10..30]);
        assert_eq!(
            parts[1].content_range,
            ContentRange::Bytes { range: ByteRange { start: 10, end: 29 }, complete_length: Some(content.len() as u64) }
        );
    }
}
