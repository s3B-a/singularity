use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    expires: Option<u64>,
    max_age: Option<i64>,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: None,
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = value.into();
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    pub fn set_domain(&mut self, domain: impl Into<String>) {
        self.domain = Some(domain.into());
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn set_path(&mut self, path: Option<String>) {
        self.path = path;
    }

    pub fn expires(&self) -> Option<u64> {
        self.expires
    }

    pub fn set_expires(&mut self, expires: Option<u64>) {
        self.expires = expires;
    }

    pub fn max_age(&self) -> Option<i64> {
        self.max_age
    }

    pub fn set_max_age(&mut self, max_age: Option<i64>) {
        self.max_age = max_age;
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    pub fn set_secure(&mut self, secure: bool) {
        self.secure = secure;
    }

    pub fn is_http_only(&self) -> bool {
        self.http_only
    }

    pub fn set_http_only(&mut self, http_only: bool) {
        self.http_only = http_only;
    }

    pub fn same_site(&self) -> Option<SameSite> {
        self.same_site.clone()
    }

    pub fn set_same_site(&mut self, same_site: Option<SameSite>) {
        self.same_site = same_site;
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            return now >= expires;
        }

        if let Some(max_age) = self.max_age {
            return max_age <= 0;
        }

        false
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        match &self.domain {
            Some(cookie_domain) => {
                domain == cookie_domain || domain.ends_with(&format!(".{}", cookie_domain))
            }
            None => true,
        }
    }

    pub fn matches_path(&self, path: &str) -> bool {
        match &self.path {
            Some(cookie_path) => path.starts_with(cookie_path),
            None => true,
        }
    }

    pub fn to_header_value(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)?;
        
        if let Some(domain) = &self.domain {
            write!(f, "; Domain={}", domain)?;
        }
        
        if let Some(path) = &self.path {
            write!(f, "; Path={}", path)?;
        }
        
        if let Some(expires) = self.expires {
            write!(f, "; Expires={}", expires)?;
        }
        
        if let Some(max_age) = self.max_age {
            write!(f, "; Max-Age={}", max_age)?;
        }
        
        if self.secure {
            write!(f, "; Secure")?;
        }
        
        if self.http_only {
            write!(f, "; HttpOnly")?;
        }
        
        if let Some(same_site) = self.same_site.clone() {
            write!(f, "; SameSite={}", match same_site {
                SameSite::Strict => "Strict",
                SameSite::Lax => "Lax",
                SameSite::None => "None",
            })?;
        }
        
        Ok(())
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
        }
    }
}