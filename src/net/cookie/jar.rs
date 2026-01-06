use super::cookie::Cookie;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CookieJar {
    cookies: HashMap<String, Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
        }
    }

    pub fn add(&mut self, cookie: Cookie) {
        let key = self.make_key(&cookie);
        self.cookies.insert(key, cookie);
    }

    pub fn get(&self, name: &str) -> Option<&Cookie> {
        self.cookies.values().find(|c| c.name() == name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Cookie> {
        self.cookies.values_mut().find(|c| c.name() == name)
    }

    pub fn remove(&mut self, name: &str) -> Option<Cookie> {
        let key = self.cookies.iter().find(|(_, c)| c.name() == name).map(|(k, _)| k.clone())?;
        self.cookies.remove(&key)
    }

    pub fn get_matching(&self, domain: &str, path: &str, secure: bool) -> Vec<&Cookie> {
        self.cookies.values().filter(|cookie| {
            !cookie.is_expired()
            && cookie.matches_domain(domain)
            && cookie.matches_path(path)
            && (!cookie.is_secure() || secure)
        }).collect()
    }

    pub fn all(&self) -> Vec<&Cookie> {
        self.cookies.values().collect()
    }

    pub fn remove_expired(&mut self) {
        self.cookies.retain(|_, cookie| !cookie.is_expired());
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    pub fn cookie_header(&self, domain: &str, path: &str, secure: bool) -> Option<String> {
        let cookies = self.get_matching(domain, path, secure);
        if cookies.is_empty() {
            return None;
        }

        let header = cookies.iter().map(|c| c.to_header_value()).collect::<Vec<_>>().join("; ");

        Some(header)
    }

    fn make_key(&self, cookie: &Cookie) -> String {
        format!("{};{};{}", cookie.name(), cookie.domain().unwrap_or(""), cookie.path().unwrap_or("/"))
    }

    pub fn merge(&mut self, other: &CookieJar) {
        for cookie in other.all() {
            self.add(cookie.clone());
        }
    }

    pub fn cookies_for_domain(&self, domain: &str) -> Vec<&Cookie> {
        self.cookies.values().filter(|cookie| cookie.matches_domain(domain)).collect()
    }

    pub fn set(&mut self, cookie: Cookie) {
        self.add(cookie);
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn names(&self) -> Vec<String> {
        self.cookies.values().map(|c| c.name().to_string()).collect()
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<Cookie> for CookieJar {
    fn from_iter<T: IntoIterator<Item=Cookie>>(iter: T) -> Self {
        let mut jar = CookieJar::new();
        for cookie in iter {
            jar.add(cookie);
        }
        jar
    }
}

impl Extend<Cookie> for CookieJar {
    fn extend<T: IntoIterator<Item=Cookie>>(&mut self, iter: T) {
        for cookie in iter {
            self.add(cookie);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_cookie() {
        let mut jar = CookieJar::new();
        let cookie = Cookie::new("session", "abc123");
        jar.add(cookie);

        assert_eq!(jar.len(), 1);
        assert!(jar.contains("session"));
        assert_eq!(jar.get("session").unwrap().value(), "abc123");
    }

    #[test]
    fn test_remove_cookie() {
        let mut jar = CookieJar::new();
        jar.add(Cookie::new("session", "abc123"));
        
        let removed = jar.remove("session");
        assert!(removed.is_some());
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn test_cookie_matching() {
        let mut jar = CookieJar::new();
        let mut cookie = Cookie::new("test", "value");
        cookie.set_domain("example.com".to_string());
        cookie.set_path(Some("/api".to_string()));
        jar.add(cookie);

        let matches = jar.get_matching("example.com", "/api/v1", false);
        assert_eq!(matches.len(), 1);

        let no_matches = jar.get_matching("other.com", "/api/v1", false);
        assert_eq!(no_matches.len(), 0);
    }

    #[test]
    fn test_cookie_header() {
        let mut jar = CookieJar::new();
        jar.add(Cookie::new("session", "abc123"));
        jar.add(Cookie::new("token", "xyz789"));

        let header = jar.cookie_header("example.com", "/", false).unwrap();
        assert!(header.contains("session=abc123"));
        assert!(header.contains("token=xyz789"));
    }
}