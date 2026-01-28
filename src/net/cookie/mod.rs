pub mod cookie;
pub mod jar;
pub mod parser;

pub use jar::CookieJar;
pub use cookie::{Cookie, SameSite};
pub use parser::{parse_cookie_header, parse_set_cookie, ParseError};

// Convenience function for new cookies
pub fn new_cookie(name: impl Into<String>, value: impl Into<String>) -> Cookie {
    Cookie::new(name, value)
}

// Convenience function for new jars
pub fn new_jar() -> CookieJar {
    CookieJar::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_cookie() {
        let cookie = new_cookie("test", "value");
        assert_eq!(cookie.name(), "test");
        assert_eq!(cookie.value(), "value");
    }

    #[test]
    fn test_create_jar() {
        let jar = new_jar();
        assert!(jar.is_empty());
    }

    #[test]
    fn test_parse_and_store() {
        let mut jar = new_jar();
        let cookie = parse_set_cookie("session=abc123; Path=/; Secure").unwrap();
        jar.add(cookie);

        assert_eq!(jar.len(), 1);
        let stored = jar.get("session").unwrap();
        assert_eq!(stored.value(), "abc123");
        assert!(stored.is_secure());
    }

    #[test]
    fn test_cookie_lifecycle() {
        let mut jar = new_jar();
        
        let cookie1 = parse_set_cookie("session=abc; Domain=example.com; Path=/").unwrap();
        let cookie2 = parse_set_cookie("token=xyz; Domain=example.com; Path=/api").unwrap();
        jar.add(cookie1);
        jar.add(cookie2);

        let matches = jar.get_matching("example.com", "/api/test", false);
        assert_eq!(matches.len(), 2);

        let header = jar.cookie_header("example.com", "/api", false).unwrap();
        assert!(header.contains("session=abc"));
        assert!(header.contains("token=xyz"));

        jar.remove("session");
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn test_same_site_attribute() {
        let cookie = parse_set_cookie("test=value; SameSite=Strict").unwrap();
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));

        let cookie = parse_set_cookie("test=value; SameSite=Lax").unwrap();
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));

        let cookie = parse_set_cookie("test=value; SameSite=None").unwrap();
        assert_eq!(cookie.same_site(), Some(SameSite::None));
    }
}