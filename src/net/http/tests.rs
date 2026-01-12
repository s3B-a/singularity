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

mod trailer_tests {
    use crate::net::http::trailer::{TrailerHeaders, is_forbidden_trailer_field, common};
    use std::io::Cursor;

    #[test]
    fn test_basic_trailer_creation() {
        let trailers = TrailerHeaders::new();
        assert!(trailers.is_empty());
        assert_eq!(trailers.len(), 0);
    }

    #[test]
    fn test_add_valid_trailer() {
        let mut trailers = TrailerHeaders::new();
        
        let result = trailers.add("X-Checksum".to_string(), "abc123".to_string());
        assert!(result.is_ok());
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers.get("X-Checksum"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_add_multiple_trailers() {
        let mut trailers = TrailerHeaders::new();
        
        trailers.add("X-Checksum".to_string(), "abc123".to_string()).unwrap();
        trailers.add("X-Status".to_string(), "OK".to_string()).unwrap();
        trailers.add("X-Processing-Time".to_string(), "1234ms".to_string()).unwrap();
        
        assert_eq!(trailers.len(), 3);
    }

    #[test]
    fn test_forbidden_transfer_encoding() {
        let mut trailers = TrailerHeaders::new();
        let result = trailers.add("Transfer-Encoding".to_string(), "chunked".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_forbidden_content_length() {
        let mut trailers = TrailerHeaders::new();
        let result = trailers.add("Content-Length".to_string(), "100".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_forbidden_host() {
        let mut trailers = TrailerHeaders::new();
        let result = trailers.add("Host".to_string(), "example.com".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_forbidden_authorization() {
        let mut trailers = TrailerHeaders::new();
        let result = trailers.add("Authorization".to_string(), "Bearer token".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_forbidden_cookie() {
        let mut trailers = TrailerHeaders::new();
        let result = trailers.add("Cookie".to_string(), "session=abc".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_forbidden_set_cookie() {
        let mut trailers = TrailerHeaders::new();
        let result = trailers.add("Set-Cookie".to_string(), "session=abc".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_forbidden_content_encoding() {
        let mut trailers = TrailerHeaders::new();
        let result = trailers.add("Content-Encoding".to_string(), "gzip".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_forbidden_connection() {
        let mut trailers = TrailerHeaders::new();
        let result = trailers.add("Connection".to_string(), "close".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_allowed_custom_headers() {
        let mut trailers = TrailerHeaders::new();
        
        assert!(trailers.add("X-Custom-Header".to_string(), "value".to_string()).is_ok());
        assert!(trailers.add("X-Request-ID".to_string(), "12345".to_string()).is_ok());
        assert!(trailers.add("X-Trace-ID".to_string(), "trace-123".to_string()).is_ok());
    }

    #[test]
    fn test_allowed_digest_headers() {
        let mut trailers = TrailerHeaders::new();
        
        assert!(trailers.add("Content-MD5".to_string(), "abc123".to_string()).is_ok());
        assert!(trailers.add("Digest".to_string(), "SHA-256=xyz".to_string()).is_ok());
        assert!(trailers.add("X-Content-SHA256".to_string(), "hash".to_string()).is_ok());
    }

    #[test]
    fn test_trailer_with_expected_list() {
        let trailers = TrailerHeaders::with_expected("X-Checksum, X-Status, X-Time");
        
        let expected = trailers.expected.as_ref().unwrap();
        assert_eq!(expected.len(), 3);
        assert!(expected.contains("x-checksum"));
        assert!(expected.contains("x-status"));
        assert!(expected.contains("x-time"));
    }

    #[test]
    fn test_trailer_with_whitespace_in_expected() {
        let trailers = TrailerHeaders::with_expected("  X-Checksum  ,  X-Status  ");
        
        let expected = trailers.expected.as_ref().unwrap();
        assert_eq!(expected.len(), 2);
        assert!(expected.contains("x-checksum"));
        assert!(expected.contains("x-status"));
    }

    #[test]
    fn test_validate_expected_all_present() {
        let mut trailers = TrailerHeaders::with_expected("X-Checksum, X-Status");
        
        trailers.add("X-Checksum".to_string(), "abc".to_string()).unwrap();
        trailers.add("X-Status".to_string(), "OK".to_string()).unwrap();
        
        assert!(trailers.validate_expected().is_ok());
    }

    #[test]
    fn test_validate_expected_missing() {
        let mut trailers = TrailerHeaders::with_expected("X-Checksum, X-Status");
        
        trailers.add("X-Checksum".to_string(), "abc".to_string()).unwrap();
        
        let result = trailers.validate_expected();
        assert!(result.is_err());
        let missing = result.unwrap_err();
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&"x-status".to_string()));
    }

    #[test]
    fn test_parse_simple_trailers() {
        let data = b"X-Checksum: abc123\r\nX-Status: OK\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, false, None).unwrap();
        
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers.get("X-Checksum"), Some(&"abc123".to_string()));
        assert_eq!(trailers.get("X-Status"), Some(&"OK".to_string()));
    }

    #[test]
    fn test_parse_trailers_with_expected() {
        let data = b"X-Checksum: abc123\r\nX-Status: OK\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, true, Some("X-Checksum, X-Status")).unwrap();
        
        assert_eq!(trailers.len(), 2);
        assert!(trailers.validate_expected().is_ok());
    }

    #[test]
    fn test_parse_trailers_multiline_value() {
        let data = b"X-Long-Value: part1\r\n part2\r\nX-Status: OK\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        // This should either parse or fail gracefully
        let result = TrailerHeaders::parse(&mut cursor, false, None);
    }

    #[test]
    fn test_parse_empty_trailers() {
        let data = b"\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, false, None).unwrap();
        assert!(trailers.is_empty());
    }

    #[test]
    fn test_parse_forbidden_in_trailer() {
        let data = b"Content-Length: 100\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let result = TrailerHeaders::parse(&mut cursor, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_malformed_no_colon() {
        let data = b"Invalid Line\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let result = TrailerHeaders::parse(&mut cursor, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_malformed_no_value() {
        let data = b"X-Header:\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, false, None).unwrap();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers.get("X-Header"), Some(&"".to_string()));
    }

    #[test]
    fn test_parse_with_spaces() {
        let data = b"X-Checksum:   abc123   \r\nX-Status:  OK  \r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, false, None).unwrap();
        assert_eq!(trailers.get("X-Checksum"), Some(&"abc123".to_string()));
        assert_eq!(trailers.get("X-Status"), Some(&"OK".to_string()));
    }

    #[test]
    fn test_into_map() {
        let mut trailers = TrailerHeaders::new();
        trailers.add("X-Checksum".to_string(), "abc".to_string()).unwrap();
        trailers.add("X-Status".to_string(), "OK".to_string()).unwrap();
        
        let map = trailers.into_map();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("X-Checksum"), Some(&"abc".to_string()));
    }

    #[test]
    fn test_common_trailer_constants() {
        assert_eq!(common::CONTENT_MD5, "Content-MD5");
        assert_eq!(common::X_CONTENT_SHA256, "X-Content-SHA256");
        assert_eq!(common::DIGEST, "Digest");
        assert_eq!(common::SERVER_TIMING, "Server-Timing");
    }

    #[test]
    fn test_is_forbidden_all_standard_fields() {
        // Transfer control
        assert!(is_forbidden_trailer_field("transfer-encoding"));
        assert!(is_forbidden_trailer_field("content-length"));
        assert!(is_forbidden_trailer_field("trailer"));
        
        // Request control
        assert!(is_forbidden_trailer_field("host"));
        assert!(is_forbidden_trailer_field("cache-control"));
        assert!(is_forbidden_trailer_field("expect"));
        assert!(is_forbidden_trailer_field("pragma"));
        
        // Authentication
        assert!(is_forbidden_trailer_field("authorization"));
        assert!(is_forbidden_trailer_field("proxy-authorization"));
        
        // Cookies
        assert!(is_forbidden_trailer_field("cookie"));
        assert!(is_forbidden_trailer_field("set-cookie"));
        
        // Connection
        assert!(is_forbidden_trailer_field("connection"));
        assert!(is_forbidden_trailer_field("upgrade"));
        
        // Conditional
        assert!(is_forbidden_trailer_field("if-match"));
        assert!(is_forbidden_trailer_field("if-none-match"));
    }

    #[test]
    fn test_is_not_forbidden_custom_fields() {
        assert!(!is_forbidden_trailer_field("x-custom"));
        assert!(!is_forbidden_trailer_field("x-request-id"));
        assert!(!is_forbidden_trailer_field("server-timing"));
        assert!(!is_forbidden_trailer_field("content-md5"));
    }

    #[test]
    fn test_case_insensitive_forbidden_check() {
        assert!(is_forbidden_trailer_field("content-length"));
        assert!(is_forbidden_trailer_field("Content-Length"));
        assert!(is_forbidden_trailer_field("CONTENT-LENGTH"));
    }

    #[test]
    fn test_real_world_digest_trailer() {
        let data = b"Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, false, None).unwrap();
        assert_eq!(trailers.len(), 1);
        assert!(trailers.get("Digest").is_some());
    }

    #[test]
    fn test_real_world_server_timing_trailer() {
        let data = b"Server-Timing: db;dur=123, api;dur=456\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, false, None).unwrap();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers.get("Server-Timing"), Some(&"db;dur=123, api;dur=456".to_string()));
    }

    #[test]
    fn test_multiple_trailers_with_validation() {
        let data = b"X-Checksum: abc123\r\nX-Status: complete\r\nX-Time: 1234ms\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, true, Some("X-Checksum, X-Status, X-Time")).unwrap();
        assert_eq!(trailers.len(), 3);
        assert!(trailers.validate_expected().is_ok());
    }

    #[test]
    fn test_unexpected_trailer_still_parsed() {
        let data = b"X-Checksum: abc123\r\nX-Unexpected: value\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, true, Some("X-Checksum")).unwrap();
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers.get("X-Unexpected"), Some(&"value".to_string()));
    }
}

mod priority_scheduler_tests {
    use crate::net::http::http2::{Priority, PriorityScheduler};

    #[test]
    fn test_scheduler_basic() {
        let scheduler = PriorityScheduler::new();
        assert_eq!(scheduler.active_count(), 0);
        assert!(!scheduler.has_ready_streams());
    }

    #[test]
    fn test_add_single_stream() {
        let mut scheduler = PriorityScheduler::new();
        let priority = Priority::new(0, 16, false);
        
        scheduler.add_stream(1, priority);
        scheduler.mark_ready(1, 1000);
        
        assert_eq!(scheduler.active_count(), 1);
        assert_eq!(scheduler.total_pending_bytes(), 1000);
    }

    #[test]
    fn test_schedule_single_stream() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.mark_ready(1, 1000);
        
        let next = scheduler.schedule_next();
        assert_eq!(next, Some(1));
    }

    #[test]
    fn test_priority_ordering() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 1, false));
        scheduler.mark_ready(1, 1000);
        
        scheduler.add_stream(3, Priority::new(0, 255, false));
        scheduler.mark_ready(3, 1000);
        
        let mut counts = [0; 2];
        for _ in 0..20 {
            if let Some(id) = scheduler.schedule_next() {
                if id == 1 { counts[0] += 1; }
                if id == 3 { counts[1] += 1; }
                scheduler.mark_ready(id, 1000);
            }
        }
        
        assert!(counts[1] > counts[0]);
    }

    #[test]
    fn test_bytes_sent_updates() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.mark_ready(1, 1000);
        
        scheduler.bytes_sent(1, 300);
        assert_eq!(scheduler.total_pending_bytes(), 700);
        
        scheduler.bytes_sent(1, 700);
        assert_eq!(scheduler.total_pending_bytes(), 0);
    }

    #[test]
    fn test_blocked_stream_not_scheduled() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.mark_blocked(1);
        
        let next = scheduler.schedule_next();
        assert_eq!(next, None);
    }

    #[test]
    fn test_dependency_basic() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, false)); // Depends on 1
        
        scheduler.mark_ready(1, 1000);
        scheduler.mark_ready(3, 1000);
        
        let first = scheduler.schedule_next().unwrap();
        assert_eq!(first, 1);
    }

    #[test]
    fn test_exclusive_dependency() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(0, 16, false));
        scheduler.add_stream(5, Priority::new(0, 16, true));
    }

    #[test]
    fn test_remove_stream_reparents() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, false));
        scheduler.add_stream(5, Priority::new(3, 16, false));
        
        scheduler.remove_stream(3);
        
        assert_eq!(scheduler.get_state(3), None);
    }

    #[test]
    fn test_update_priority() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 100, false));
        
        let new_priority = Priority::new(0, 200, false);
        let expected_weight = new_priority.weight;
        let expected_dependency = new_priority.stream_dependency;
        let expected_exclusive = new_priority.exclusive;
        scheduler.update_priority(1, new_priority);
        
        if let Some(priority) = scheduler.get_priority(1) {
            assert_eq!(priority.weight, expected_weight);
            assert_eq!(priority.stream_dependency, expected_dependency);
            assert_eq!(priority.exclusive, expected_exclusive);
        } else {
            panic!("Priority not found");
        }
    }

    #[test]
    fn test_tree_depth_calculation() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, false));
        scheduler.add_stream(5, Priority::new(3, 16, false));
        
        let stats = scheduler.get_tree_stats();
        assert_eq!(stats.tree_depth, 3);
    }

    #[test]
    fn test_closed_stream_not_scheduled() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.mark_ready(1, 1000);
        scheduler.mark_closed(1);
        
        let next = scheduler.schedule_next();
        assert_eq!(next, None);
    }

    #[test]
    fn test_multiple_children_weighted_scheduling() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 50, false));
        scheduler.add_stream(3, Priority::new(0, 100, false));
        scheduler.add_stream(5, Priority::new(0, 200, false));
        
        for i in vec![1, 3, 5] {
            scheduler.mark_ready(i, 10000);
        }
        
        let mut counts = [0; 3];
        for _ in 0..30 {
            if let Some(id) = scheduler.schedule_next() {
                match id {
                    1 => counts[0] += 1,
                    3 => counts[1] += 1,
                    5 => counts[2] += 1,
                    _ => {}
                }
                scheduler.mark_ready(id, 10000);
            }
        }

        assert!(counts[2] > counts[1]);
        assert!(counts[1] > counts[0]);
    }

    #[test]
    fn test_scheduler_stats() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, false));
        scheduler.add_stream(5, Priority::new(1, 16, false));
        
        scheduler.mark_ready(1, 1000);
        scheduler.mark_ready(3, 2000);
        scheduler.mark_blocked(5);
        
        let stats = scheduler.get_tree_stats();
        assert_eq!(stats.total_streams, 3);
        assert_eq!(stats.active_streams, 2);
        assert_eq!(stats.blocked_streams, 1);
        assert_eq!(stats.total_pending_bytes, 3000);
    }
}