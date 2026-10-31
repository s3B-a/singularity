use super::headers::Headers;
use super::method::HttpMethod;
use crate::crypto::hash::sha2::sha256;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTag {
    pub weak: bool,
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityTagMatch {
    Any,
    Tags(Vec<EntityTag>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionOutcome {
    Proceed,
    NotModified,
    PreconditionFailed,
}

impl EntityTag {
    pub fn strong(tag: impl Into<String>) -> Self {
        Self { weak: false, tag: tag.into() }
    }

    pub fn weak(tag: impl Into<String>) -> Self {
        Self { weak: true, tag: tag.into() }
    }

    pub fn from_content(content: &[u8]) -> Self {
        let digest = sha256(content);
        Self::strong(digest[..16].iter().map(|b| format!("{:02x}", b)).collect::<String>())
    }

    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let (weak, quoted) = match value.strip_prefix("W/") {
            Some(rest) => (true, rest),
            None => (false, value),
        };

        let tag = quoted.strip_prefix('"')?.strip_suffix('"')?;
        if !tag.bytes().all(is_etagc) {
            return None;
        }

        Some(Self { weak, tag: tag.to_string() })
    }

    pub fn strong_eq(&self, other: &EntityTag) -> bool {
        !self.weak && !other.weak && self.tag == other.tag
    }

    pub fn weak_eq(&self, other: &EntityTag) -> bool {
        self.tag == other.tag
    }

    pub fn into_weak(self) -> Self {
        Self { weak: true, tag: self.tag }
    }
}

impl EntityTagMatch {
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value == "*" {
            return Some(EntityTagMatch::Any);
        }

        let bytes = value.as_bytes();
        let mut tags = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t' | b',') {
                pos += 1;
            }

            if pos >= bytes.len() {
                break;
            }

            let start = pos;
            if bytes[pos..].starts_with(b"W/") {
                pos += 2;
            }

            if bytes.get(pos) != Some(&b'"') {
                return None;
            }

            pos += 1;
            let close = bytes[pos..].iter().position(|&b| b == b'"')?;
            pos += close + 1;
            tags.push(EntityTag::parse(&value[start..pos])?);

            while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
                pos += 1;
            }

            if pos < bytes.len() && bytes[pos] != b',' {
                return None;
            }
        }

        if tags.is_empty() {
            None
        } else {
            Some(EntityTagMatch::Tags(tags))
        }
    }
}

fn is_etagc(b: u8) -> bool {
    b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80
}

pub fn format_http_date(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[((days + 4).rem_euclid(7)) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        secs_of_day / 3600,
        (secs_of_day / 60) % 60,
        secs_of_day % 60
    )
}

pub fn http_date_now() -> String {
    format_http_date(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs())
}

pub fn parse_http_date(value: &str) -> Option<u64> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let (year, month, day, time) = match parts.as_slice() {
        // Sun, 06 Nov 1994 08:49:37 GMT
        [weekday, day, month, year, time, "GMT"] if weekday.ends_with(',') => {
            (year.parse::<i64>().ok()?, month_index(month)?, day.parse::<u32>().ok()?, *time)
        }
        // Sunday, 06-Nov-94 08:49:37 GMT
        [weekday, date, time, "GMT"] if weekday.ends_with(',') => {
            let mut fields = date.split('-');
            let day = fields.next()?.parse::<u32>().ok()?;
            let month = month_index(fields.next()?)?;
            let short_year = fields.next()?;
            if fields.next().is_some() || short_year.len() != 2 {
                return None;
            }

            let yy = short_year.parse::<i64>().ok()?;
            (if yy < 70 { 2000 + yy } else { 1900 + yy }, month, day, *time)
        }
        // Sun Nov  6 08:49:37 1994
        [_weekday, month, day, time, year] => {
            (year.parse::<i64>().ok()?, month_index(month)?, day.parse::<u32>().ok()?, *time)
        }
        _ => return None,
    };

    let mut clock = time.split(':');
    let hour = clock.next()?.parse::<u64>().ok()?;
    let minute = clock.next()?.parse::<u64>().ok()?;
    let second = clock.next()?.parse::<u64>().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }

    Some(days as u64 * 86_400 + hour * 3600 + minute * 60 + second.min(59))
}

fn month_index(name: &str) -> Option<u32> {
    MONTHS.iter().position(|m| m.eq_ignore_ascii_case(name)).map(|i| i as u32 + 1)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = (if year >= 0 { year } else { year - 399 }) / 400;
    let yoe = year - era * 400;
    let month = month as i64;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

pub fn evaluate_preconditions(method: HttpMethod, headers: &Headers, etag: Option<&EntityTag>, last_modified: Option<u64>) -> PreconditionOutcome {
    let is_get_or_head = matches!(method, HttpMethod::GET | HttpMethod::HEAD);

    if let Some(if_match) = headers.get("if-match").and_then(EntityTagMatch::parse) {
        let passes = match if_match {
            EntityTagMatch::Any => etag.is_some(),
            EntityTagMatch::Tags(tags) => etag.map(|current| tags.iter().any(|t| t.strong_eq(current))).unwrap_or(false),
        };

        if !passes {
            return PreconditionOutcome::PreconditionFailed;
        }
    } else if let (Some(since), Some(modified)) = (headers.get("if-unmodified-since").and_then(parse_http_date), last_modified) {
        if modified > since {
            return PreconditionOutcome::PreconditionFailed;
        }
    }

    if let Some(if_none_match) = headers.get("if-none-match").and_then(EntityTagMatch::parse) {
        let matched = match if_none_match {
            EntityTagMatch::Any => etag.is_some(),
            EntityTagMatch::Tags(tags) => etag.map(|current| tags.iter().any(|t| t.weak_eq(current))).unwrap_or(false),
        };

        if matched {
            return if is_get_or_head {
                PreconditionOutcome::NotModified
            } else {
                PreconditionOutcome::PreconditionFailed
            };
        }
    } else if is_get_or_head {
        if let (Some(since), Some(modified)) = (headers.get("if-modified-since").and_then(parse_http_date), last_modified) {
            if modified <= since {
                return PreconditionOutcome::NotModified;
            }
        }
    }

    PreconditionOutcome::Proceed
}

pub fn if_range_matches(value: &str, etag: Option<&EntityTag>, last_modified: Option<u64>) -> bool {
    let value = value.trim();
    if value.starts_with('"') || value.starts_with("W/") {
        return match (EntityTag::parse(value), etag) {
            (Some(condition), Some(current)) => condition.strong_eq(current),
            _ => false,
        };
    }

    match (parse_http_date(value), last_modified) {
        (Some(date), Some(modified)) => date == modified,
        _ => false,
    }
}

impl fmt::Display for EntityTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.weak {
            write!(f, "W/\"{}\"", self.tag)
        } else {
            write!(f, "\"{}\"", self.tag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Headers {
        let mut headers = Headers::new();
        for (name, value) in pairs {
            headers.append(*name, *value);
        }

        headers
    }

    #[test]
    fn test_http_date_formats_roundtrip() {
        assert_eq!(format_http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(format_http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");

        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(784_111_777));
        assert_eq!(parse_http_date(&format_http_date(1_700_000_000)), Some(1_700_000_000));
    }

    #[test]
    fn test_http_date_rejects_garbage() {
        for value in ["", "yesterday", "Sun, 06 Nov 1994 25:49:37 GMT", "Sun, 32 Nov 1994 08:49:37 GMT", "Sun, 06 Foo 1994 08:49:37 GMT", "Sun, 06 Nov 1994 08:49:37 PST"] {
            assert_eq!(parse_http_date(value), None, "{:?}", value);
        }
    }

    #[test]
    fn test_entity_tag_parsing_and_comparison() {
        let strong = EntityTag::parse("\"xyzzy\"").unwrap();
        let weak = EntityTag::parse("W/\"xyzzy\"").unwrap();
        assert!(!strong.weak && weak.weak);
        assert!(strong.weak_eq(&weak));
        assert!(!strong.strong_eq(&weak));
        assert!(strong.strong_eq(&EntityTag::strong("xyzzy")));
        assert_eq!(weak.to_string(), "W/\"xyzzy\"");
        assert_eq!(EntityTag::parse("xyzzy"), None);
        assert_eq!(EntityTag::parse("\"a\"b\""), None);
    }

    #[test]
    fn test_entity_tag_list_allows_commas_inside_tags() {
        assert_eq!(EntityTagMatch::parse("*"), Some(EntityTagMatch::Any));
        assert_eq!(
            EntityTagMatch::parse("\"a,b\", W/\"c\""),
            Some(EntityTagMatch::Tags(vec![EntityTag::strong("a,b"), EntityTag::weak("c")]))
        );
        assert_eq!(EntityTagMatch::parse("\"a\" junk"), None);
        assert_eq!(EntityTagMatch::parse(""), None);
    }

    #[test]
    fn test_if_none_match_yields_not_modified_for_get() {
        let etag = EntityTag::strong("v1");
        let h = headers(&[("If-None-Match", "W/\"v1\"")]);
        assert_eq!(evaluate_preconditions(HttpMethod::GET, &h, Some(&etag), None), PreconditionOutcome::NotModified);
        assert_eq!(evaluate_preconditions(HttpMethod::PUT, &h, Some(&etag), None), PreconditionOutcome::PreconditionFailed);

        let other = headers(&[("If-None-Match", "\"v0\"")]);
        assert_eq!(evaluate_preconditions(HttpMethod::GET, &other, Some(&etag), None), PreconditionOutcome::Proceed);
    }

    #[test]
    fn test_if_none_match_takes_precedence_over_if_modified_since() {
        let etag = EntityTag::strong("v2");
        let h = headers(&[("If-None-Match", "\"v1\""), ("If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT")]);
        assert_eq!(evaluate_preconditions(HttpMethod::GET, &h, Some(&etag), Some(784_111_777)), PreconditionOutcome::Proceed);
    }

    #[test]
    fn test_if_modified_since() {
        let h = headers(&[("If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT")]);
        assert_eq!(evaluate_preconditions(HttpMethod::GET, &h, None, Some(784_111_777)), PreconditionOutcome::NotModified);
        assert_eq!(evaluate_preconditions(HttpMethod::GET, &h, None, Some(784_111_778)), PreconditionOutcome::Proceed);
        assert_eq!(evaluate_preconditions(HttpMethod::POST, &h, None, Some(784_111_777)), PreconditionOutcome::Proceed);
        assert_eq!(evaluate_preconditions(HttpMethod::GET, &h, None, None), PreconditionOutcome::Proceed);

        let invalid = headers(&[("If-Modified-Since", "not a date")]);
        assert_eq!(evaluate_preconditions(HttpMethod::GET, &invalid, None, Some(1)), PreconditionOutcome::Proceed);
    }

    #[test]
    fn test_if_match_requires_strong_match() {
        let etag = EntityTag::strong("v1");
        assert_eq!(evaluate_preconditions(HttpMethod::PUT, &headers(&[("If-Match", "\"v1\"")]), Some(&etag), None), PreconditionOutcome::Proceed);
        assert_eq!(evaluate_preconditions(HttpMethod::PUT, &headers(&[("If-Match", "W/\"v1\"")]), Some(&etag), None), PreconditionOutcome::PreconditionFailed);
        assert_eq!(evaluate_preconditions(HttpMethod::PUT, &headers(&[("If-Match", "*")]), Some(&etag), None), PreconditionOutcome::Proceed);
        assert_eq!(evaluate_preconditions(HttpMethod::PUT, &headers(&[("If-Match", "*")]), None, None), PreconditionOutcome::PreconditionFailed);
    }

    #[test]
    fn test_if_unmodified_since() {
        let h = headers(&[("If-Unmodified-Since", "Sun, 06 Nov 1994 08:49:37 GMT")]);
        assert_eq!(evaluate_preconditions(HttpMethod::PUT, &h, None, Some(784_111_777)), PreconditionOutcome::Proceed);
        assert_eq!(evaluate_preconditions(HttpMethod::PUT, &h, None, Some(784_111_778)), PreconditionOutcome::PreconditionFailed);
    }

    #[test]
    fn test_if_range() {
        let etag = EntityTag::strong("v1");
        assert!(if_range_matches("\"v1\"", Some(&etag), None));
        assert!(!if_range_matches("W/\"v1\"", Some(&EntityTag::weak("v1")), None));
        assert!(!if_range_matches("\"v0\"", Some(&etag), None));
        assert!(if_range_matches("Sun, 06 Nov 1994 08:49:37 GMT", None, Some(784_111_777)));
        assert!(!if_range_matches("Sun, 06 Nov 1994 08:49:37 GMT", None, Some(784_111_778)));
    }
}