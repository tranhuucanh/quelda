//! Parser layer (design §4.1): bytes → normalized objects. Knows nothing
//! about rules or policy.

pub mod lexer;
pub mod object;
pub mod parse;

pub use object::{Dict, Name, ObjRef, PdfObject, PdfStream, StreamLength};
pub use parse::{IndirectObject, ParseError, ParseErrorKind, parse_indirect_object, parse_object};
