use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone)]
pub struct Headers {
    headers: HashMap<String, Vec<String>>,
}

impl Headers {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = Self::normalize_name(name.into());
        self.headers.insert(name, vec![value.into()]);
    }

    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = Self::normalize_name(name.into());
        self.headers.entry(name).or_insert_with(Vec::new).push(value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let name = Self::normalize_name(name.to_string());
        self.headers.get(&name).and_then(|values| values.first().map(|s| s.as_str()))
    }

    pub fn get_all(&self, name: &str) -> Option<&[String]> {
        let name = Self::normalize_name(name.to_string());
        self.headers.get(&name).map(|values| values.as_slice())
    }

    pub fn contains(&self, name: &str) -> bool {
        let name = Self::normalize_name(name.to_string());
        self.headers.contains_key(&name)
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<String>> {
        let name = Self::normalize_name(name.to_string());
        self.headers.remove(&name)
    }

    pub fn names(&self) -> Vec<String> {
        self.headers.keys().cloned().collect()
    }

    pub fn iter(&self) ->impl Iterator<Item = (&String, &Vec<String>)> {
        self.headers.iter()
    }

    fn normalize_name(name: String) -> String {
        name.trim().to_ascii_lowercase()
    }

    pub fn parse(lines: &[String]) -> Self {
        let mut headers = Self::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.append(name.trim(), value.trim());
            }
        }

        headers
    }

    pub fn format(&self) -> String {
        let mut result = String::new();
        for (name, val) in &self.headers {
            for v in val {
                result.push_str(&format!("{}: {}\r\n", Self::capitalize_name(name), v))
            }
        }

        result
    }

    fn capitalize_name(name: &str) -> String {
        name.split('-').map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        }).collect::<Vec<_>>().join("-")
    }

    pub fn content_length(&self) -> Option<usize> {
        self.get("content-length").and_then(|v| v.parse().ok())
    }

    pub fn is_keep_alive(&self) -> bool {
        self.get("connection").map(|v| v.to_lowercase() == "keep-alive").unwrap_or(false)
    }

    pub fn is_chunked(&self) -> bool {
        self.get("transfer-encoding").map(|v| v.to_lowercase().contains("chunked")).unwrap_or(false)
    }

    pub fn into_map(self) -> HashMap<String, String> {
        self.headers.into_iter().map(|(k, v)| {
            (k, v.join(", "))
        }).collect()
    }

    pub fn ensure_keep_alive(&mut self) {
        if !self.contains("connection") {
            self.insert("Connection", "keep-alive");
        }
    }

    pub fn has_keep_alive(&self) -> bool {
        self.get("connection").map(|v| v.to_lowercase().contains("keep-alive")).unwrap_or(false)
    }

    pub fn set_connection_type(&mut self, connection_type: &str) {
        self.insert("Connection", connection_type);
    }

    pub fn connection_type(&self) -> String {
        self.get("connection").unwrap_or("keep-alive").to_string()
    }

    pub fn clone_for_connection(&self) -> Self {
        let mut new_headers = self.clone();
        new_headers.ensure_keep_alive();
        new_headers
    }
}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}