//! Engine issues: problems that stop the engine from inspecting (part of) the
//! input. Any issue makes the verdict `ERROR`, `valid: false` (design §4.5).
//! Issues are not rule findings and cannot be turned off by policy.

use std::fmt;

/// Stable issue code, reported in the verdict as `errors[].code`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IssueCode {
    /// Bytes that must be parsed are not valid PDF syntax.
    EngineParse,
    /// Arrays/dictionaries nested deeper than `max_nesting_depth`.
    LimitNestingDepth,
    /// All streams together decode to more than `max_decoded_bytes_total`.
    LimitDecodedBytes,
    /// One stream decodes to more than `max_decoded_bytes_per_stream`.
    LimitStreamDecodedBytes,
    /// One stream decodes to more than `max_compression_ratio` × its raw size.
    LimitCompressionRatio,
    /// More filters on one stream than the engine will run.
    LimitFilterChain,
}

impl IssueCode {
    /// The code as written in the verdict, e.g. `LIMIT.NESTING_DEPTH`.
    pub fn as_str(self) -> &'static str {
        match self {
            IssueCode::EngineParse => "ENGINE.PARSE",
            IssueCode::LimitNestingDepth => "LIMIT.NESTING_DEPTH",
            IssueCode::LimitDecodedBytes => "LIMIT.DECODED_BYTES",
            IssueCode::LimitStreamDecodedBytes => "LIMIT.STREAM_DECODED_BYTES",
            IssueCode::LimitCompressionRatio => "LIMIT.COMPRESSION_RATIO",
            IssueCode::LimitFilterChain => "LIMIT.FILTER_CHAIN",
        }
    }

    /// `true` for `LIMIT.*` codes (a configured limit was exceeded).
    pub fn is_limit(self) -> bool {
        self.as_str().starts_with("LIMIT.")
    }
}

impl fmt::Display for IssueCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One engine issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineIssue {
    pub code: IssueCode,
    /// Byte offset in the input, when the issue has one.
    pub offset: Option<usize>,
    pub message: String,
}

impl EngineIssue {
    pub fn new(code: IssueCode, offset: Option<usize>, message: impl Into<String>) -> Self {
        EngineIssue {
            code,
            offset,
            message: message.into(),
        }
    }
}

impl fmt::Display for EngineIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(off) => write!(f, "{} at offset {off}: {}", self.code, self.message),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_strings() {
        assert_eq!(IssueCode::EngineParse.as_str(), "ENGINE.PARSE");
        assert_eq!(IssueCode::LimitNestingDepth.as_str(), "LIMIT.NESTING_DEPTH");
        assert_eq!(IssueCode::LimitDecodedBytes.as_str(), "LIMIT.DECODED_BYTES");
        assert_eq!(
            IssueCode::LimitStreamDecodedBytes.as_str(),
            "LIMIT.STREAM_DECODED_BYTES"
        );
        assert_eq!(
            IssueCode::LimitCompressionRatio.as_str(),
            "LIMIT.COMPRESSION_RATIO"
        );
        assert_eq!(IssueCode::LimitFilterChain.as_str(), "LIMIT.FILTER_CHAIN");
    }

    #[test]
    fn limit_codes_are_flagged() {
        assert!(IssueCode::LimitNestingDepth.is_limit());
        assert!(IssueCode::LimitCompressionRatio.is_limit());
        assert!(!IssueCode::EngineParse.is_limit());
    }

    #[test]
    fn display_includes_offset() {
        let i = EngineIssue::new(IssueCode::EngineParse, Some(42), "bad token");
        assert_eq!(i.to_string(), "ENGINE.PARSE at offset 42: bad token");
        let i = EngineIssue::new(IssueCode::EngineParse, None, "bad");
        assert_eq!(i.to_string(), "ENGINE.PARSE: bad");
    }
}
