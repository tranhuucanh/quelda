//! Parser layer (design §4.1): bytes → normalized objects. Knows nothing
//! about rules or policy.

pub mod document;
pub mod lexer;
pub mod linear_scan;
pub mod object;
pub mod objstm;
pub mod parse;
pub mod structure;
pub mod xref;

pub use document::Document;
pub use object::{Dict, Name, ObjRef, PdfObject, PdfStream, StreamLength};
pub use parse::{
    IndirectObject, ParseError, ParseErrorKind, object_header_at, parse_indirect_object,
    parse_indirect_object_extent, parse_object, parse_object_extent,
};
