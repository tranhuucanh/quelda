//! Short random / mutated inputs: the lexer and parser must return (an error
//! or a value) without panicking and without looping. Deterministic: a fixed
//! xorshift seed, so failures reproduce.

use quelda_core::limits::Limits;
use quelda_core::parser::lexer::Lexer;
use quelda_core::parser::{parse_indirect_object, parse_object};

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Bytes biased towards PDF syntax so inputs reach deep parser paths.
const ALPHABET: &[u8] = b"0123456789 .+-\n\r\t%/#()<>[]{}\\RobjendstreamtrufalsnulABJS";

fn random_input(rng: &mut XorShift) -> Vec<u8> {
    let len = rng.below(300);
    (0..len)
        .map(|_| {
            if rng.below(8) == 0 {
                rng.next() as u8
            } else {
                ALPHABET[rng.below(ALPHABET.len())]
            }
        })
        .collect()
}

fn exercise(input: &[u8]) {
    let limits = Limits {
        max_nesting_depth: 16,
        ..Limits::default()
    };
    let mut lx = Lexer::new(input);
    let mut steps = 0;
    loop {
        let before = lx.pos();
        match lx.next_token() {
            Ok(None) => break,
            Ok(Some(_)) | Err(_) => assert!(lx.pos() > before, "lexer stuck at {before}"),
        }
        steps += 1;
        assert!(steps <= input.len() + 1);
    }
    for off in [0, input.len() / 3, input.len() / 2] {
        if let Ok((_, end)) = parse_object(input, off, &limits) {
            assert!(end <= input.len());
        }
        if let Ok(o) = parse_indirect_object(input, off, &limits) {
            assert!(o.end <= input.len());
            if let Some(s) = o.object.as_stream() {
                assert!(s.data.start <= s.data.end && s.data.end <= input.len());
            }
        }
    }
}

#[test]
fn random_inputs_do_not_panic() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for _ in 0..500 {
        exercise(&random_input(&mut rng));
    }
}

#[test]
fn truncations_and_mutations_do_not_panic() {
    let obj: &[u8] = b"7 0 obj\n<< /Type /Annot /A << /S /#4A#53 /JS (a\\(b\\)\\101) \
        /K [1 0 R <4A53> -.5 true null] >> /Length 4 >>\nstream\r\nabcd\nendstream\nendobj\n";
    assert!(parse_indirect_object(obj, 0, &Limits::default()).is_ok());
    for cut in 0..obj.len() {
        exercise(&obj[..cut]);
    }
    let mut rng = XorShift(42);
    for _ in 0..300 {
        let mut m = obj.to_vec();
        for _ in 0..1 + rng.below(3) {
            let i = rng.below(m.len());
            m[i] = ALPHABET[rng.below(ALPHABET.len())];
        }
        exercise(&m);
    }
}

#[test]
fn degenerate_inputs() {
    for input in [
        &b""[..],
        b"(",
        b"<",
        b"<<",
        b"[",
        b"/",
        b"\\",
        b"%",
        b")",
        b">",
        b"1 0 obj",
        b"1 0 obj << >> stream",
        b"1 0 obj << /Length 5 >> stream\r\n",
        &[0u8; 64],
        &[0xFFu8; 64],
    ] {
        exercise(input);
    }
}
