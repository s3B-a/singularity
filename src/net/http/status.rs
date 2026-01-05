use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(u16);

impl StatusCode {
    pub fn new(code: u16) -> Self {
        StatusCode(code)
    }

    pub fn code(&self) -> u16 {
        self.0
    }

    pub fn is_informational(&self) -> bool {
        (100..200).contains(&self.0)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    pub fn is_redirection(&self) -> bool {
        (300..400).contains(&self.0)
    }

    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            102 => "Processing",
            103 => "Early Hints",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            208 => "Already Reported",
            226 => "IM Used",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            306 => "Switch Proxy",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            418 => "I'm a teapot",
            421 => "Misdirected Request",
            422 => "Unprocessable Entity",
            423 => "Locked",
            424 => "Failed Dependency",
            425 => "Too Early",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            506 => "Variant Also Negotiates",
            507 => "Insufficient Storage",
            508 => "Loop Detected",
            510 => "Not Extended",
            511 => "Network Authentication Required",
            _ => "Unknown Status Code",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason_phrase())
    }
}

impl StatusCode {
    pub const CONTINUE: StatusCode = StatusCode(100);
    pub const SWITCHING_PROTOCOLS: StatusCode = StatusCode(101);
    pub const PROCESSING: StatusCode = StatusCode(102);
    pub const EARLY_HINTS: StatusCode = StatusCode(103);
    pub const OK: StatusCode = StatusCode(200);
    pub const CREATED: StatusCode = StatusCode(201);
    pub const ACCEPTED: StatusCode = StatusCode(202);
    pub const NON_AUTHORITATIVE_INFORMATION: StatusCode = StatusCode(203);
    pub const NO_CONTENT: StatusCode = StatusCode(204);
    pub const RESET_CONTENT: StatusCode = StatusCode(205);
    pub const PARTIAL_CONTENT: StatusCode = StatusCode(206);
    pub const MULTI_STATUS: StatusCode = StatusCode(207);
    pub const ALREADY_REPORTED: StatusCode = StatusCode(208);
    pub const IM_USED: StatusCode = StatusCode(226);
    pub const MULTIPLE_CHOICES: StatusCode = StatusCode(300);
    pub const MOVED_PERMANENTLY: StatusCode = StatusCode(301);
    pub const FOUND: StatusCode = StatusCode(302);
    pub const SEE_OTHER: StatusCode = StatusCode(303);
    pub const NOT_MODIFIED: StatusCode = StatusCode(304);
    pub const USE_PROXY: StatusCode = StatusCode(305);
    pub const SWITCH_PROXY: StatusCode = StatusCode(306);
    pub const TEMPORARY_REDIRECT: StatusCode = StatusCode(307);
    pub const PERMANENT_REDIRECT: StatusCode = StatusCode(308);
    pub const BAD_REQUEST: StatusCode = StatusCode(400);
    pub const UNAUTHORIZED: StatusCode = StatusCode(401);
    pub const PAYMENT_REQUIRED: StatusCode = StatusCode(402);
    pub const FORBIDDEN: StatusCode = StatusCode(403);
    pub const NOT_FOUND: StatusCode = StatusCode(404);
    pub const METHOD_NOT_ALLOWED: StatusCode = StatusCode(405);
    pub const NOT_ACCEPTABLE: StatusCode = StatusCode(406);
    pub const PROXY_AUTHENTICATION_REQUIRED: StatusCode = StatusCode(407);
    pub const REQUEST_TIMEOUT: StatusCode = StatusCode(408);
    pub const CONFLICT: StatusCode = StatusCode(409);
    pub const GONE: StatusCode = StatusCode(410);
    pub const LENGTH_REQUIRED: StatusCode = StatusCode(411);
    pub const PRECONDITION_FAILED: StatusCode = StatusCode(412);
    pub const PAYLOAD_TOO_LARGE: StatusCode = StatusCode(413);
    pub const URI_TOO_LONG: StatusCode = StatusCode(414);
    pub const UNSUPPORTED_MEDIA_TYPE: StatusCode = StatusCode(415);
    pub const RANGE_NOT_SATISFIABLE: StatusCode = StatusCode(416);
    pub const EXPECTATION_FAILED: StatusCode = StatusCode(417);
    pub const IM_A_TEAPOT: StatusCode = StatusCode(418);
    pub const MISDIRECTED_REQUEST: StatusCode = StatusCode(421);
    pub const UNPROCESSABLE_ENTITY: StatusCode = StatusCode(422);
    pub const LOCKED: StatusCode = StatusCode(423);
    pub const FAILED_DEPENDENCY: StatusCode = StatusCode(424);
    pub const TOO_EARLY: StatusCode = StatusCode(425);
    pub const UPGRADE_REQUIRED: StatusCode = StatusCode(426);
    pub const PREDICITON_REQUIRED: StatusCode = StatusCode(428);
    pub const TOO_MANY_REQUESTS: StatusCode = StatusCode(429);
    pub const REQUEST_HEADER_FIELDS_TOO_LARGE: StatusCode = StatusCode(431);
    pub const UNAVAILABLE_FOR_LEGAL_REASONS: StatusCode = StatusCode(451);
    pub const INTERNAL_SERVER_ERROR: StatusCode = StatusCode(500);
    pub const NOT_IMPLEMENTED: StatusCode = StatusCode(501);
    pub const BAD_GATEWAY: StatusCode = StatusCode(502);
    pub const SERVICE_UNAVAILABLE: StatusCode = StatusCode(503);
    pub const GATEWAY_TIMEOUT: StatusCode = StatusCode(504);
    pub const HTTP_VERSION_NOT_SUPPORTED: StatusCode = StatusCode(505);
    pub const VARIANT_ALSO_NEGOTIATES: StatusCode = StatusCode(506);
    pub const INSUFFICIENT_STORAGE: StatusCode = StatusCode(507);
    pub const LOOP_DETECTED: StatusCode = StatusCode(508);
    pub const NOT_EXTENDED: StatusCode = StatusCode(510);
    pub const NETWORK_AUTHENTICATION_REQUIRED: StatusCode = StatusCode(511);
}