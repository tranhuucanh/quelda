//! Lexer, object parser and content-stream tokenizer on arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quelda_core::facts::content_ops;
use quelda_core::limits::Limits;
use quelda_core::parser::lexer::Lexer;
use quelda_core::parser::{parse_indirect_object, parse_object};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();

    let mut lex = Lexer::new(data);
    while let Ok(Some(_)) = lex.next_token() {}

    let _ = parse_object(data, 0, &limits);
    let _ = parse_indirect_object(data, 0, &limits);

    let mut ops = 0usize;
    let _ = content_ops::tokenize(data, &limits, |_| ops += 1);
});
