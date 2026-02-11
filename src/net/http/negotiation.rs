use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct MediaType {
    pub type_: String,
    pub subtype: String,
    pub quality: f32,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct LanguageTag {
    pub language: String,
    pub region: Option<String>,
    pub quality: f32,
}

#[derive(Debug, Clone)]
pub struct EncodingPreference {
    pub encoding: String,
    pub quality: f32,
}

pub struct ContentNegotiator;

impl MediaType {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(';').map(|p| p.trim()).collect();
        if parts.is_empty() {
            return None;
        }

        let media_parts: Vec<&str> = parts[0].split('/').collect();
        if media_parts.len() != 2 {
            return None;
        }

        let mut quality = 1.0;
        let mut params = Vec::new();
        for param in &parts[1..] {
            if let Some((key, value)) = param.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                if key == "q" {
                    quality = value.parse().unwrap_or(1.0);
                } else {
                    params.push((key.to_string(), value.to_string()));
                }
            }
        }

        Some(MediaType {
            type_: media_parts[0].to_string(),
            subtype: media_parts[1].to_string(),
            quality,
            params,
        })
    }

    pub fn matches(&self, other: &MediaType) -> bool {
        (self.type_ == "*" || other.type_ == "*" || self.type_ == other.type_) &&
        (self.subtype == "*" || other.subtype == "*" || self.subtype == other.subtype)
    }

    pub fn specificity(&self) -> u8 {
        if self.type_ == "*" {
            0
        } else if self.subtype == "*" {
            1
        } else {
            2
        }
    }

    pub fn to_string(&self) -> String {
        let mut result = format!("{}/{}", self.type_, self.subtype);
        for (key, value) in &self.params {
            result.push_str(&format!("; {}={}", key, value));
        }
        
        result
    }
}

impl LanguageTag {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(';').map(|p| p.trim()).collect();
        if parts.is_empty() {
            return None;
        }

        let lang_parts: Vec<&str> = parts[0].split('-').collect();
        let language = lang_parts[0].to_string();
        let region = if lang_parts.len() > 1 {
            Some(lang_parts[1].to_string())
        } else {
            None
        };

        let mut quality = 1.0;
        for param in &parts[1..] {
            if let Some((key, value)) = param.split_once('=') {
                if key.trim() == "q" {
                    quality = value.trim().parse().unwrap_or(1.0);
                }
            }
        }

        Some(LanguageTag {
            language,
            region,
            quality,
        })
    }

    pub fn matches(&self, other: &LanguageTag) -> bool {
        if self.language == "*" || other.language == "*" {
            return true;
        }
        
        if self.language != other.language {
            return false;
        }
        
        match (&self.region, &other.region) {
            (None, _) | (_, None) => true,
            (Some(r1), Some(r2)) => r1 == r2,
        }
    }
    
    pub fn to_string(&self) -> String {
        if let Some(ref region) = self.region {
            format!("{}-{}", self.language, region)
        } else {
            self.language.clone()
        }
    }
}

impl EncodingPreference {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(';').map(|p| p.trim()).collect();
        if parts.is_empty() {
            return None;
        }
        
        let encoding = parts[0].to_string();
        let mut quality = 1.0;
        for param in &parts[1..] {
            if let Some((key, value)) = param.split_once('=') {
                if key.trim() == "q" {
                    quality = value.trim().parse().unwrap_or(1.0);
                }
            }
        }
        
        Some(EncodingPreference {
            encoding,
            quality,
        })
    }
}

impl ContentNegotiator {
    pub fn negotiate_media_type(accept: &str, available: &[&str]) -> Option<String> {
        let mut client_prefs: Vec<MediaType> = accept.split(',').filter_map(|s| MediaType::parse(s.trim())).collect();
        
        client_prefs.sort();
        
        let server_types: Vec<MediaType> = available.iter().filter_map(|s| MediaType::parse(s)).collect();
        for client_type in &client_prefs {
            for server_type in &server_types {
                if client_type.matches(server_type) {
                    return Some(server_type.to_string());
                }
            }
        }
        
        None
    }
    
    pub fn negotiate_language(accept_language: &str, available: &[&str]) -> Option<String> {
        let mut client_prefs: Vec<LanguageTag> = accept_language.split(',').filter_map(|s| LanguageTag::parse(s.trim())).collect();
        client_prefs.sort();
        let server_langs: Vec<LanguageTag> = available.iter().filter_map(|s| LanguageTag::parse(s)).collect();
        for client_lang in &client_prefs {
            for server_lang in &server_langs {
                if client_lang.matches(server_lang) {
                    return Some(server_lang.to_string());
                }
            }
        }
        
        None
    }
    
    pub fn negotiate_encoding(accept_encoding: &str, available: &[&str]) -> Option<String> {
        let mut client_prefs: Vec<EncodingPreference> = accept_encoding.split(',').filter_map(|s| EncodingPreference::parse(s.trim())).collect();
        
        client_prefs.sort();
        for pref in &client_prefs {
            if pref.encoding == "*" {
                return available.first().map(|s| s.to_string());
            }
            
            for &encoding in available {
                if pref.encoding.eq_ignore_ascii_case(encoding) {
                    return Some(encoding.to_string());
                }
            }
        }
        
        if client_prefs.iter().any(|p| p.encoding == "identity") {
            return Some("identity".to_string());
        }
        
        None
    }
    
    pub fn parse_accept(accept: &str) -> Vec<MediaType> {
        let mut types: Vec<MediaType> = accept.split(',').filter_map(|s| MediaType::parse(s.trim())).collect();
        types.sort();

        types
    }
    
    pub fn parse_accept_language(accept_language: &str) -> Vec<LanguageTag> {
        let mut langs: Vec<LanguageTag> = accept_language.split(',').filter_map(|s| LanguageTag::parse(s.trim())).collect();
        langs.sort();

        langs
    }
    
    pub fn parse_accept_encoding(accept_encoding: &str) -> Vec<EncodingPreference> {
        let mut encodings: Vec<EncodingPreference> = accept_encoding.split(',').filter_map(|s| EncodingPreference::parse(s.trim())).collect();
        encodings.sort();

        encodings
    }
}

impl PartialEq for MediaType {
    fn eq(&self, other: &Self) -> bool {
        self.type_ == other.type_ && self.subtype == other.subtype
    }
}

impl Eq for MediaType {}

impl PartialOrd for MediaType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MediaType {
    fn cmp(&self, other: &Self) -> Ordering {
        let quality_cmp = other.quality.partial_cmp(&self.quality).unwrap_or(Ordering::Equal);
        if quality_cmp != Ordering::Equal {
            return quality_cmp;
        }

        other.specificity().cmp(&self.specificity())
    }
}


impl PartialEq for LanguageTag {
    fn eq(&self, other: &Self) -> bool {
        self.language == other.language && self.region == other.region
    }
}

impl Eq for LanguageTag {}

impl PartialOrd for LanguageTag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LanguageTag {
    fn cmp(&self, other: &Self) -> Ordering {
        other.quality.partial_cmp(&self.quality).unwrap_or(Ordering::Equal)
    }
}

impl PartialEq for EncodingPreference {
    fn eq(&self, other: &Self) -> bool {
        self.encoding.eq_ignore_ascii_case(&other.encoding)
    }
}

impl Eq for EncodingPreference {}

impl PartialOrd for EncodingPreference {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EncodingPreference {
    fn cmp(&self, other: &Self) -> Ordering {
        other.quality.partial_cmp(&self.quality).unwrap_or(Ordering::Equal)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_media_type_parse() {
        let mt = MediaType::parse("text/html; q=0.8").unwrap();
        assert_eq!(mt.type_, "text");
        assert_eq!(mt.subtype, "html");
        assert_eq!(mt.quality, 0.8);
    }
    
    #[test]
    fn test_media_type_wildcard() {
        let mt1 = MediaType::parse("text/*").unwrap();
        let mt2 = MediaType::parse("text/html").unwrap();
        assert!(mt1.matches(&mt2));
    }
    
    #[test]
    fn test_negotiate_media_type() {
        let result = ContentNegotiator::negotiate_media_type(
            "text/html, application/json; q=0.9, */*; q=0.1",
            &["application/json", "text/plain"],
        );
        assert_eq!(result, Some("application/json".to_string()));
    }
    
    #[test]
    fn test_language_tag_parse() {
        let lang = LanguageTag::parse("en-US; q=0.9").unwrap();
        assert_eq!(lang.language, "en");
        assert_eq!(lang.region, Some("US".to_string()));
        assert_eq!(lang.quality, 0.9);
    }
    
    #[test]
    fn test_negotiate_language() {
        let result = ContentNegotiator::negotiate_language(
            "en-US, en; q=0.9, fr; q=0.8",
            &["en", "de"],
        );
        assert_eq!(result, Some("en".to_string()));
    }
    
    #[test]
    fn test_negotiate_encoding() {
        let result = ContentNegotiator::negotiate_encoding(
            "gzip, deflate; q=0.8",
            &["deflate", "identity"],
        );
        assert_eq!(result, Some("deflate".to_string()));
    }
}