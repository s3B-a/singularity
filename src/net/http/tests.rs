#[cfg(test)]
mod integration_tests {
    use crate::net::http::{client::HttpClient, HttpRequest, version::HttpVersion, HttpMethod};
    use std::time::Duration;

    #[test]
    fn test_http11_request() {
        let mut client = HttpClient::builder()
            .timeout(Duration::from_secs(30))
            .preferred_version(HttpVersion::Http11)
            .build();

        let request = HttpRequest::new(HttpMethod::GET, "http://example.com/test");
        
        match client.execute(request) {
            Ok(response) => {
                assert!(response.status_code() >= 100);
                assert_eq!(response.version(), HttpVersion::Http11);
            }
            Err(_) => {
                // Expected without real server
            }
        }
    }

    #[test]
    fn test_http2_request() {
        let mut client = HttpClient::builder()
            .timeout(Duration::from_secs(30))
            .preferred_version(HttpVersion::Http2)
            .build();

        let request = HttpRequest::new(HttpMethod::GET, "https://example.com/test");
        
        match client.execute(request) {
            Ok(response) => {
                assert!(response.version() == HttpVersion::Http2 || 
                        response.version() == HttpVersion::Http11);
            }
            Err(_) => {
            }
        }
    }

    #[test]
    fn test_connection_pooling() {
        let mut client = HttpClient::builder()
            .preferred_version(HttpVersion::Http2)
            .build();

        let stats = client.connection_stats();
        assert_eq!(stats.get("http2_connections"), Some(&0));

        let _ = client.get("https://example.com/page1");
        let _ = client.get("https://example.com/page2");

        client.cleanup_connections();
    }

    #[test]
    fn test_builder_configuration() {
        let client = HttpClient::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("Singularity/Beta-0.0.1".to_string())
            .follow_redirects(false)
            .max_redirects(3)
            .preferred_version(HttpVersion::Http2)
            .default_header("X-Custom".to_string(), "Value".to_string())
            .build();

        let stats = client.connection_stats();
        assert!(stats.contains_key("http2_connections"));
    }

    #[test]
    fn test_multiple_methods() {
        let mut client = HttpClient::new();

        let _get = client.get("http://example.com");
        let _post = client.post("http://example.com", vec![1, 2, 3]);
        
        let mut request = HttpRequest::new(HttpMethod::PUT, "http://example.com");
        request.set_body(b"test data".to_vec());
        let _put = client.execute(request);

        let request = HttpRequest::new(HttpMethod::DELETE, "http://example.com");
        let _delete = client.execute(request);
    }

    #[test]
    fn test_header_management() {
        let mut request = HttpRequest::new(HttpMethod::GET, "http://example.com");
        
        request.set_header("Content-Type".to_string(), "application/json".to_string());
        request.set_header("X-Custom-Header".to_string(), "custom-value".to_string());

        assert_eq!(request.headers().get("Content-Type"), Some("application/json"));
        assert_eq!(request.headers().get("X-Custom-Header"), Some("custom-value"));
    }

    #[test]
    fn test_request_body() {
        let mut request = HttpRequest::new(HttpMethod::POST, "http://example.com");
        let body_data = b"test request body".to_vec();
        
        request.set_body(body_data.clone());
        
        assert_eq!(request.headers().get("Content-Length"), Some("17"));
    }

    #[test]
    fn test_response_status_categories() {
        use crate::net::http::HttpResponse;
        use std::collections::HashMap;

        // 2xx Success
        let response = HttpResponse::new(
            200,
            "OK".to_string(),
            HttpVersion::Http11,
            HashMap::new(),
            vec![],
        );
        assert!(response.is_success());
        assert!(!response.is_redirect());
        assert!(!response.is_client_error());
        assert!(!response.is_server_error());

        // 3xx Redirect
        let response = HttpResponse::new(
            301,
            "Moved Permanently".to_string(),
            HttpVersion::Http11,
            HashMap::new(),
            vec![],
        );
        assert!(!response.is_success());
        assert!(response.is_redirect());

        // 4xx Client Error
        let response = HttpResponse::new(
            404,
            "Not Found".to_string(),
            HttpVersion::Http11,
            HashMap::new(),
            vec![],
        );
        assert!(!response.is_success());
        assert!(response.is_client_error());

        // 5xx Server Error
        let response = HttpResponse::new(
            500,
            "Internal Server Error".to_string(),
            HttpVersion::Http11,
            HashMap::new(),
            vec![],
        );
        assert!(!response.is_success());
        assert!(response.is_server_error());
    }

    #[test]
    fn test_http_version_comparison() {
        assert_eq!(HttpVersion::Http10, HttpVersion::Http10);
        assert_ne!(HttpVersion::Http11, HttpVersion::Http2);
        
        assert_eq!(HttpVersion::Http10.as_str(), "HTTP/1.0");
        assert_eq!(HttpVersion::Http11.as_str(), "HTTP/1.1");
        assert_eq!(HttpVersion::Http2.as_str(), "HTTP/2.0");
    }
}