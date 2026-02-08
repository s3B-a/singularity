use super::Url;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    EmptyUrl,
    InvalidScheme,
    InvalidHost,
    InvalidPort,
    MissingScheme,
    InvalidUrl(String),
}

pub fn parse_url(input: &str) -> Result<Url, ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyUrl);
    }

    let mut remainder = input;
    let scheme_end = remainder.find("://").ok_or(ParseError::MissingScheme)?;
    let scheme = remainder[..scheme_end].to_lowercase();
    if !is_valid_scheme(&scheme) {
        return Err(ParseError::InvalidScheme);
    }

    remainder = &remainder[scheme_end + 3..];
    let (remainder, fragment) = if let Some(hash_pos) = remainder.find('#') {
        let frag = Some(remainder[hash_pos + 1..].to_string());
        (&remainder[..hash_pos], frag)
    } else {
        (remainder, None)
    };

    let (remainder, query) = if let Some(qmark_pos) = remainder.find('?') {
        let q = Some(remainder[qmark_pos + 1..].to_string());
        (&remainder[..qmark_pos], q)
    } else {
        (remainder, None)
    };

    let (authority, path) = if let Some(path_pos) = remainder.find('/') {
        let p = remainder[path_pos..].to_string();
        (&remainder[..path_pos], p)
    } else {
        (remainder, String::new())
    };

    let (username, password, host, port) = parse_authority(authority, &scheme)?;

    Ok(Url {
        scheme,
        username,
        password,
        host,
        port,
        path,
        query,
        fragment,
    })
}

fn parse_authority(authority: &str, scheme: &str) -> Result<(String, Option<String>, Option<String>, Option<u16>), ParseError> {
    if authority.is_empty() {
        return Ok((String::new(), None, None, None));
    }

    let mut remainder = authority;
    let (username, password, remainder) = if let Some(at_pos) = remainder.find('@') {
        let userinfo = &remainder[..at_pos];
        remainder = &remainder[at_pos + 1..];
        if let Some(colon_pos) = userinfo.find(':') {
            let user = userinfo[..colon_pos].to_string();
            let pass = Some(userinfo[colon_pos + 1..].to_string());
            (user, pass, remainder)
        } else {
            (userinfo.to_string(), None, remainder)
        }
    } else {
        (String::new(), None, remainder)
    };

    let(host, port) = if remainder.starts_with('[') {
        let end_bracket = remainder.find(']').ok_or(ParseError::InvalidHost)?;
        let ipv6_host = remainder[..=end_bracket].to_string();
        let after_bracket = &remainder[end_bracket + 1..];
        if after_bracket.starts_with(':') {
            let port_str = &after_bracket[1..];
            let port = parse_port(port_str)?;
            (Some(ipv6_host), Some(port))
        } else {
            (Some(ipv6_host), default_port(scheme))
        }
    } else if let Some(colon_pos) = remainder.rfind(':') {
        let potential_port = &remainder[colon_pos + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) {
            let host = remainder[..colon_pos].to_string();
            let port = parse_port(potential_port)?;
            (Some(host), Some(port))
        } else {
            (Some(remainder.to_string()), default_port(scheme))
        }
    } else {
        (Some(remainder.to_string()), default_port(scheme))
    };

    Ok((username, password, host, port))
}

fn parse_port(port_str: &str) -> Result<u16, ParseError> {
    port_str.parse::<u16>().map_err(|_| ParseError::InvalidPort)
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        "ftp" => Some(21),
        "ws" => Some(80),
        "wss" => Some(443),
        _ => None,
    }
}

fn is_valid_scheme(scheme: &str) -> bool {
    if scheme.is_empty() {
        return false;
    }

    let mut chars = scheme.chars();
    if let Some(first) = chars.next() {
        if !first.is_ascii_alphabetic() {
            return false;
        }
    } else {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

pub fn join_urls(base: &Url, relative: &str) -> Result<Url, ParseError> {
    if relative.contains("://") {
        return parse_url(relative);
    }

    let mut result = base.clone();
    if relative.starts_with("//") {
        return parse_url(&format!("{}:{}", base.scheme(), relative));
    } else if relative.starts_with('/') {
        if let Some(query_pos) = relative.find('?') {
            result.set_path(relative[..query_pos].to_string());
            let after_query = &relative[query_pos + 1..];
            if let Some(fragment_pos) = after_query.find('#') {
                result.set_query(Some(after_query[..fragment_pos].to_string()));
                result.set_fragment(Some(after_query[fragment_pos + 1..].to_string()));
            } else {
                result.set_query(Some(after_query.to_string()));
                result.set_fragment(None::<String>);
            }
        } else if let Some(fragment_pos) = relative.find('#') {
            result.set_path(relative[..fragment_pos].to_string());
            result.set_query(None::<String>);
            result.set_fragment(Some(relative[fragment_pos + 1..].to_string()));
        } else {
            result.set_path(relative.to_string());
            result.set_query(None::<String>);
            result.set_fragment(None::<String>);
        }
    } else if relative.starts_with('?') {
        if let Some(fragment_pos) = relative.find('#') {
            result.set_query(Some(relative[1..fragment_pos].to_string()));
            result.set_fragment(Some(relative[fragment_pos + 1..].to_string()));
        } else {
            result.set_query(Some(relative[1..].to_string()));
            result.set_fragment(None::<String>);
        }
    } else if relative.starts_with('#') {
        result.set_fragment(Some(relative[1..].to_string()));
    } else {
        let base_path = base.path();
        let new_path = if base_path.ends_with('/') {
            format!("{}{}", base_path, relative)
        } else {
            if let Some(last_slash) = base_path.rfind('/') {
                format!("{}/{}", &base_path[..last_slash], relative)
            } else {
                format!("/{}", relative)
            }
        };

        let normalized = normalize_path(&new_path);
        if let Some(query_pos) = normalized.find('?') {
            result.set_path(normalized[..query_pos].to_string());
            let after_query = &normalized[query_pos + 1..];
            if let Some(fragment_pos) = after_query.find('#') {
                result.set_query(Some(after_query[..fragment_pos].to_string()));
                result.set_fragment(Some(after_query[fragment_pos + 1..].to_string()));
            } else {
                result.set_query(Some(after_query.to_string()));
                result.set_fragment(None::<String>);
            }
        } else if let Some(fragment_pos) = normalized.find('#') {
            result.set_path(normalized[..fragment_pos].to_string());
            result.set_query(None::<String>);
            result.set_fragment(Some(normalized[fragment_pos + 1..].to_string()));
        } else {
            result.set_path(normalized);
            result.set_query(None::<String>);
            result.set_fragment(None::<String>);
        }
    }

    Ok(result)
}

fn normalize_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {
                if segments.is_empty() {
                    segments.push("");
                }
            }
            ".." => {
                if segments.len() > 1 {
                    segments.pop();
                }
            }
            _ => segments.push(segment),
        }
    }

    if segments.is_empty() {
        "/".to_string()
    } else {
        segments.join("/")
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::EmptyUrl => write!(f, "URL is empty"),
            ParseError::InvalidScheme => write!(f, "Invalid URL scheme"),
            ParseError::InvalidHost => write!(f, "Invalid URL host"),
            ParseError::InvalidPort => write!(f, "Invalid URL port"),
            ParseError::MissingScheme => write!(f, "Missing URL scheme"),
            ParseError::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_url() {
        let url = parse_url("https://example.com/path").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host(), Some("example.com"));
        assert_eq!(url.path(), "/path");
        assert_eq!(url.port(), Some(443));
    }

    #[test]
    fn test_parse_url_with_port() {
        let url = parse_url("http://example.com:8080/path").unwrap();
        assert_eq!(url.port(), Some(8080));
    }

    #[test]
    fn test_parse_url_with_query() {
        let url = parse_url("https://example.com/path?key=value&foo=bar").unwrap();
        assert_eq!(url.query(), Some("key=value&foo=bar"));
    }

    #[test]
    fn test_parse_url_with_fragment() {
        let url = parse_url("https://example.com/path#section").unwrap();
        assert_eq!(url.fragment(), Some("section"));
    }

    #[test]
    fn test_parse_url_with_userinfo() {
        let url = parse_url("https://user:pass@example.com/path").unwrap();
        assert_eq!(url.username(), "user");
        assert_eq!(url.password(), Some("pass"));
    }

    #[test]
    fn test_parse_url_complete() {
        let url = parse_url("https://user:pass@example.com:8080/path?key=value#fragment").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.username(), "user");
        assert_eq!(url.password(), Some("pass"));
        assert_eq!(url.host(), Some("example.com"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/path");
        assert_eq!(url.query(), Some("key=value"));
        assert_eq!(url.fragment(), Some("fragment"));
    }

    #[test]
    fn test_invalid_scheme() {
        assert!(parse_url("ht!tp://example.com").is_err());
    }

    #[test]
    fn test_missing_scheme() {
        assert!(parse_url("example.com/path").is_err());
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_path("/a/./b"), "/a/b");
        assert_eq!(normalize_path("/a//b"), "/a/b");
    }

    #[test]
    fn test_join_absolute_path() {
        let base = parse_url("https://example.com/a/b/c").unwrap();
        let joined = join_urls(&base, "/x/y/z").unwrap();
        assert_eq!(joined.path(), "/x/y/z");
    }

    #[test]
    fn test_join_relative_path() {
        let base = parse_url("https://example.com/a/b/c").unwrap();
        let joined = join_urls(&base, "d/e").unwrap();
        assert_eq!(joined.path(), "/a/b/d/e");
    }

    #[test]
    fn test_join_query() {
        let base = parse_url("https://example.com/path").unwrap();
        let joined = join_urls(&base, "?key=value").unwrap();
        assert_eq!(joined.query(), Some("key=value"));
    }

    #[test]
    fn test_join_fragment() {
        let base = parse_url("https://example.com/path").unwrap();
        let joined = join_urls(&base, "#section").unwrap();
        assert_eq!(joined.fragment(), Some("section"));
    }
}