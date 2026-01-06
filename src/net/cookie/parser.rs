use super::cookie::{Cookie, SameSite};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    Empty,
    InvalidFormat,
    EmptyName,
    InvalidDate,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Empty => write!(f, "Empty cookie header"),
            ParseError::InvalidFormat => write!(f, "Invalid cookie format"),
            ParseError::EmptyName => write!(f, "Empty cookie name"),
            ParseError::InvalidDate => write!(f, "Invalid date format"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse_set_cookie(header: &str) -> Result<Cookie, ParseError> {
    let parts: Vec<&str> = header.split(';').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return Err(ParseError::Empty);
    }

    let (name, value) = parse_name_value(parts[0])?;
    let mut cookie = Cookie::new(name, value);
    for part in &parts[1..] {
        parse_attributes(&mut cookie, part)?;
    }

    Ok(cookie)
}

pub fn parse_cookie_header(header: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for pair in header.split(';').map(|s| s.trim()) {
        if let Ok((name, value)) = parse_name_value(pair) {
            cookies.insert(name, value);
        }
    }

    cookies
}

fn parse_name_value(pair: &str) -> Result<(String, String), ParseError> {
    let mut parts = pair.splitn(2, '=');
    let name = parts.next().ok_or(ParseError::InvalidFormat)?.trim().to_string();
    if name.is_empty() {
        return Err(ParseError::EmptyName);
    }

    let value = parts.next().unwrap_or("").trim().to_string();

    Ok((name, value))
}

fn parse_attributes(cookie: &mut Cookie, attr: &str) -> Result<(), ParseError> {
    if attr.is_empty() {
        return Ok(());
    }

    let attr_lower = attr.to_lowercase();
    if attr_lower == "secure" {
        cookie.set_secure(true);
        return Ok(())
    }

    if attr_lower == "httponly" {
        cookie.set_http_only(true);
        return Ok(());
    }

    if let Some(eq_pos) = attr.find('=') {
        let (key, value) = attr.split_at(eq_pos);
        let key = key.trim().to_lowercase();
        let value = value[1..].trim();
        match key.as_str() {
            "domain" => {
                cookie.set_domain(value.to_string());
            }
            "path" => {
                cookie.set_path(Some(value.to_string()));
            }
            "expires" => {
                if let Ok(timestamp) = parse_expires(value) {
                    cookie.set_expires(Some(timestamp));
                }
            }
            "max_age" => {
                if let Ok(age) = value.parse::<i64>() {
                    cookie.set_max_age(Some(age))
                }
            }
            "samesite" => {
                let same_site = match value.to_lowercase().as_str() {
                    "strict" => Some(SameSite::Strict),
                    "lax" => Some(SameSite::Lax),
                    "none" => Some(SameSite::None),
                    _ => None,
                };
                cookie.set_same_site(same_site);
            }
            _ => {
                // unknown
            }
        }
    }

    Ok(())
}

fn parse_expires(date_str: &str) -> Result<u64, ParseError> {
    let months: HashMap<&str, u32> = [
        ("jan", 1), ("feb", 2), ("mar", 3), ("apr", 4),
        ("may", 5), ("jun", 6), ("jul", 7), ("aug", 8),
        ("sep", 9), ("oct", 10), ("nov", 11), ("dec", 12),
    ].iter().cloned().collect();
    
    let cleaned = date_str
        .replace(",", "")
        .replace("-", " ");
    
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(ParseError::InvalidDate);
    }
    
    // Try to parse: DD MMM YYYY HH:MM:SS
    let day = parts[0].parse::<u32>()
        .or_else(|_| parts[1].parse::<u32>())
        .map_err(|_| ParseError::InvalidDate)?;
    
    let month_str = parts[1].to_lowercase()
        .chars()
        .take(3)
        .collect::<String>();
    
    let month = months.get(month_str.as_str())
        .copied()
        .ok_or(ParseError::InvalidDate)?;
    
    let year = parts[2].parse::<u32>()
        .or_else(|_| parts[3].parse::<u32>())
        .map_err(|_| ParseError::InvalidDate)?;
    
    let year = if year < 100 {
        if year < 70 { 2000 + year } else { 1900 + year }
    } else {
        year
    };
    
    let days_since_epoch = days_since_unix_epoch(year, month, day);
    let timestamp = days_since_epoch * 86400;
    
    Ok(timestamp)
}

fn days_since_unix_epoch(year: u32, month: u32, day: u32) -> u64 {
    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    
    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += days_in_month[(m - 1) as usize] as u64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    
    days += day as u64 - 1;
    
    days
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}