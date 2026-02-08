use std::collections::HashMap;
use std::fmt;
use super::encoder::{encode_form, decode_form};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryParams {
    params: Vec<(String, String)>,
}

impl QueryParams {
    pub fn new() -> Self {
        QueryParams {
            params: Vec::new(),
        }
    }

    pub fn parse(query: &str) -> Self {
        let mut params = Vec::new();
        if query.is_empty() {
            return QueryParams { params };
        }

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }

            if let Some(eq_pos) = pair.find('=') {
                let key = &pair[..eq_pos];
                let value = &pair[eq_pos + 1..];
                let decoded_key = decode_form(key).unwrap_or_else(|_| key.to_string());
                let decoded_value = decode_form(value).unwrap_or_else(|_| value.to_string());

                params.push((decoded_key, decoded_value));
            } else {
                let decoded_key = decode_form(pair).unwrap_or_else(|_| pair.to_string());
                params.push((decoded_key, String::new()));
            }
        }

        QueryParams { params }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.params.push((key.into(), value.into()));
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.params.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_str()).collect()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.params.iter().any(|(k, _)| k == key)
    }

    pub fn remove(&mut self, key: &str) {
        self.params.retain(|(k, _)| k != key);
    }

    pub fn remove_first(&mut self, key: &str) -> Option<String> {
        if let Some(pos) = self.params.iter().position(|(k, _)| k == key) {
            Some(self.params.remove(pos).1)
        } else {
            None
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        self.remove(&key);
        self.params.push((key, value.into()));
    }

    pub fn append(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.params.push((key.into(), value.into()));
    }

    pub fn len(&self) -> usize {
        self.params.len()
    }

    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    pub fn clear(&mut self) {
        self.params.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.params.iter().map(|(k, _)| k.as_str())
    }

    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.params.iter().map(|(_, v)| v.as_str())
    }

    pub fn to_hash_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for(k, v) in &self.params {
            map.entry(k.clone()).or_insert_with(|| v.clone());
        }

        map
    }

    pub fn to_multi_map(&self) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (k, v) in &self.params {
            map.entry(k.clone()).or_insert_with(Vec::new).push(v.clone());
        }

        map
    }

    pub fn to_string(&self) -> String {
        if self.params.is_empty() {
            return String::new();
        }

        let mut result = String::new();
        for (i, (k, v)) in self.params.iter().enumerate() {
            if i > 0 {
                result.push('&');
            }

            result.push_str(&encode_form(k));
            if !v.is_empty() {
                result.push('=');
                result.push_str(&encode_form(v));
            }
        }

        result
    }

    pub fn sort(&mut self) {
        self.params.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
    }

    pub fn sorted(&self) -> Self {
        let mut sorted = self.clone();
        sorted.sort();

        sorted
    }
}

impl Default for QueryParams {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for QueryParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromIterator<(String, String)> for QueryParams {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        QueryParams {
            params: iter.into_iter().collect(),
        }
    }
}

impl<'a> FromIterator<(&'a str, &'a str)> for QueryParams {
    fn from_iter<T: IntoIterator<Item = (&'a str, &'a str)>>(iter: T) -> Self {
        QueryParams {
            params: iter
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
}

impl From<HashMap<String, String>> for QueryParams {
    fn from(map: HashMap<String, String>) -> Self {
        QueryParams {
            params: map.into_iter().collect(),
        }
    }
}

impl From<Vec<(String, String)>> for QueryParams {
    fn from(params: Vec<(String, String)>) -> Self {
        QueryParams { params }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let params = QueryParams::parse("");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_single() {
        let params = QueryParams::parse("key=value");
        assert_eq!(params.get("key"), Some("value"));
    }

    #[test]
    fn test_parse_multiple() {
        let params = QueryParams::parse("key1=value1&key2=value2&key3=value3");
        assert_eq!(params.get("key1"), Some("value1"));
        assert_eq!(params.get("key2"), Some("value2"));
        assert_eq!(params.get("key3"), Some("value3"));
    }

    #[test]
    fn test_parse_duplicate_keys() {
        let params = QueryParams::parse("key=value1&key=value2&key=value3");
        assert_eq!(params.get("key"), Some("value1")); // Gets first
        assert_eq!(params.get_all("key"), vec!["value1", "value2", "value3"]);
    }

    #[test]
    fn test_parse_no_value() {
        let params = QueryParams::parse("key1&key2=value2");
        assert_eq!(params.get("key1"), Some(""));
        assert_eq!(params.get("key2"), Some("value2"));
    }

    #[test]
    fn test_parse_encoded() {
        let params = QueryParams::parse("hello+world=foo%20bar");
        assert_eq!(params.get("hello world"), Some("foo bar"));
    }

    #[test]
    fn test_insert() {
        let mut params = QueryParams::new();
        params.insert("key", "value");
        assert_eq!(params.get("key"), Some("value"));
    }

    #[test]
    fn test_set() {
        let mut params = QueryParams::parse("key=value1&key=value2");
        params.set("key", "value3");
        assert_eq!(params.get("key"), Some("value3"));
        assert_eq!(params.get_all("key").len(), 1);
    }

    #[test]
    fn test_append() {
        let mut params = QueryParams::new();
        params.append("key", "value1");
        params.append("key", "value2");
        assert_eq!(params.get_all("key"), vec!["value1", "value2"]);
    }

    #[test]
    fn test_remove() {
        let mut params = QueryParams::parse("key1=value1&key2=value2&key1=value3");
        params.remove("key1");
        assert!(!params.contains_key("key1"));
        assert!(params.contains_key("key2"));
    }

    #[test]
    fn test_remove_first() {
        let mut params = QueryParams::parse("key=value1&key=value2");
        let removed = params.remove_first("key");
        assert_eq!(removed, Some("value1".to_string()));
        assert_eq!(params.get("key"), Some("value2"));
    }

    #[test]
    fn test_to_string() {
        let mut params = QueryParams::new();
        params.insert("key1", "value1");
        params.insert("key2", "value2");
        let query = params.to_string();
        assert!(query.contains("key1=value1"));
        assert!(query.contains("key2=value2"));
        assert!(query.contains("&"));
    }

    #[test]
    fn test_to_string_encoded() {
        let mut params = QueryParams::new();
        params.insert("hello world", "foo bar");
        let query = params.to_string();
        assert_eq!(query, "hello+world=foo+bar");
    }

    #[test]
    fn test_to_hash_map() {
        let params = QueryParams::parse("key1=value1&key2=value2&key1=value3");
        let map = params.to_hash_map();
        assert_eq!(map.get("key1"), Some(&"value1".to_string())); // First value only
        assert_eq!(map.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_to_multi_map() {
        let params = QueryParams::parse("key1=value1&key2=value2&key1=value3");
        let map = params.to_multi_map();
        assert_eq!(map.get("key1"), Some(&vec!["value1".to_string(), "value3".to_string()]));
        assert_eq!(map.get("key2"), Some(&vec!["value2".to_string()]));
    }

    #[test]
    fn test_sort() {
        let mut params = QueryParams::new();
        params.insert("zebra", "1");
        params.insert("apple", "2");
        params.insert("banana", "3");
        params.sort();
        
        let keys: Vec<&str> = params.keys().collect();
        assert_eq!(keys, vec!["apple", "banana", "zebra"]);
    }

    #[test]
    fn test_round_trip() {
        let original = "key1=value1&key2=value2&key3=value3";
        let params = QueryParams::parse(original);
        let serialized = params.to_string();
        let reparsed = QueryParams::parse(&serialized);
        
        assert_eq!(params.len(), reparsed.len());
        for (key, value) in params.iter() {
            assert_eq!(reparsed.get(key), Some(value));
        }
    }

    #[test]
    fn test_from_hash_map() {
        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());
        
        let params = QueryParams::from(map);
        assert_eq!(params.len(), 2);
        assert!(params.contains_key("key1"));
        assert!(params.contains_key("key2"));
    }

    #[test]
    fn test_iter() {
        let params = QueryParams::parse("key1=value1&key2=value2");
        let count = params.iter().count();
        assert_eq!(count, 2);
    }
}