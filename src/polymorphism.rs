use rand::Rng;

pub fn inject_junk(source: &str, rng: &mut impl Rng) -> String {
    let mut bracket_depth: i32 = 0;
    let mut fn_depth: i32 = 0; // depth inside function bodies (>0 means inside a fn)
    let mut brace_depth: i32 = 0;
    let mut pending_fn = false; // detected "fn" keyword, waiting for its body "{"
    let mut paren_depth_after_fn: i32 = 0;
    let mut last_was_open_brace = false;
    let mut in_line_comment = false;
    let mut in_string = false;
    let mut injection_points: Vec<usize> = Vec::new();

    let is_word_char = |c: char| c.is_alphanumeric() || c == '_';

    // First pass: find injection points (positions after statements inside function bodies)
    let mut pos = 0;
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\n' {
            in_line_comment = false;
            if last_was_open_brace && fn_depth > 0 {
                injection_points.push(pos + 1);
            }
            last_was_open_brace = false;
        } else if !in_line_comment && !in_string && ch == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            in_line_comment = true;
        } else if !in_line_comment {
            // Track string literals to avoid counting braces inside them
            if ch == '"' && (i == 0 || chars[i - 1] != '\\') {
                in_string = !in_string;
                last_was_open_brace = false;
            } else if !in_string {
                // Detect "fn" keyword at word boundaries
                if ch == 'n' && i >= 1 && chars[i - 1] == 'f'
                    && (i < 2 || !is_word_char(chars[i - 2]))
                    && (i + 1 >= chars.len() || !is_word_char(chars[i + 1]))
                {
                    pending_fn = true;
                    paren_depth_after_fn = 0;
                }

                // Track parens after fn keyword to find the body brace
                if pending_fn {
                    if ch == '(' { paren_depth_after_fn += 1; }
                    if ch == ')' { paren_depth_after_fn -= 1; }
                }

                if ch == '{' {
                    brace_depth += 1;
                    if fn_depth > 0 {
                        // Already inside a function body — nested blocks count too
                        fn_depth += 1;
                        last_was_open_brace = true;
                    } else if pending_fn && paren_depth_after_fn == 0 {
                        // This is the opening brace of a fn body
                        fn_depth += 1;
                        pending_fn = false;
                        last_was_open_brace = true;
                    } else {
                        // Non-function brace (mod, struct, impl, etc.)
                        pending_fn = false;
                        last_was_open_brace = false;
                    }
                } else if ch == '}' {
                    brace_depth -= 1;
                    if fn_depth > 0 {
                        fn_depth -= 1;
                    }
                    last_was_open_brace = false;
                } else if ch == '[' {
                    bracket_depth += 1;
                    last_was_open_brace = false;
                } else if ch == ']' {
                    bracket_depth -= 1;
                    last_was_open_brace = false;
                } else if ch == ';' && fn_depth > 0 && bracket_depth == 0 {
                    injection_points.push(pos + ch.len_utf8());
                    last_was_open_brace = false;
                } else if !ch.is_whitespace() {
                    last_was_open_brace = false;
                }
            }
        }
        pos += ch.len_utf8();
        i += 1;
    }

    if injection_points.is_empty() {
        return source.to_string();
    }

    // Select 3-8 random injection points
    let num_injections = rng.gen_range(3..=8).min(injection_points.len());
    let mut selected: Vec<usize> = Vec::new();
    let mut available = injection_points.clone();
    for _ in 0..num_injections {
        if available.is_empty() {
            break;
        }
        let idx = rng.gen_range(0..available.len());
        selected.push(available.remove(idx));
    }
    selected.sort_unstable();
    selected.reverse(); // Insert from end to preserve positions

    let mut modified = source.to_string();
    for point in selected {
        let junk = generate_junk_snippet(rng);
        if point <= modified.len() {
            modified.insert_str(point, &format!("\n{}\n", junk));
        }
    }

    modified
}

fn generate_junk_snippet(rng: &mut impl Rng) -> String {
    let snippet_type = rng.gen_range(0..5);
    let suffix: u32 = rng.gen_range(1000..99999);

    match snippet_type {
        0 => {
            // Type A: dead variable assignments
            let val1: u64 = rng.gen();
            let val2: u64 = rng.gen();
            format!(
                "    let _jnk_{suffix}: u64 = {val1}u64;\n    let _ = _jnk_{suffix}.wrapping_add({val2}u64);",
                suffix = suffix,
                val1 = val1,
                val2 = val2
            )
        }
        1 => {
            // Type B: no-op loops
            let count: u32 = rng.gen_range(1..4);
            format!(
                "    for _i_{suffix} in 0..{count}u32 {{\n        std::hint::black_box(_i_{suffix});\n    }}",
                suffix = suffix,
                count = count
            )
        }
        2 => {
            // Type C: dead string construction
            let val: u32 = rng.gen();
            format!(
                "    let _s_{suffix} = format!(\"{{}}\", {val}u32);\n    let _ = _s_{suffix}.len();",
                suffix = suffix,
                val = val
            )
        }
        3 => {
            // Type D: conditional that never fires
            let val1: u32 = rng.gen();
            let val2: u32 = loop {
                let v: u32 = rng.gen();
                if v != val1 {
                    break v;
                }
            };
            format!(
                "    if {val1}u32 == {val2}u32 {{\n        panic!(\"unreachable_{suffix}\");\n    }}",
                val1 = val1,
                val2 = val2,
                suffix = suffix
            )
        }
        4 => {
            // Type E: random sleep-like busy spin (0 iterations)
            format!(
                "    let _end_{suffix} = std::time::Instant::now();\n    while _end_{suffix}.elapsed().as_nanos() < 0 {{ std::hint::black_box(0u8); }}",
                suffix = suffix
            )
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_junk_produces_different_output() {
        let source = r#"fn main() {
    let x = 42;
    println!("{}", x);
}"#;
        let mut rng1 = rand::thread_rng();
        let mut rng2 = rand::thread_rng();
        let out1 = inject_junk(source, &mut rng1);
        let out2 = inject_junk(source, &mut rng2);
        // Both should differ from original
        assert_ne!(out1, source);
        assert_ne!(out2, source);
    }

    #[test]
    fn test_inject_junk_contains_black_box() {
        let source = r#"fn main() {
    let x = 1;
    let y = 2;
    let z = 3;
    let w = 4;
}"#;
        let mut rng = rand::thread_rng();
        let out = inject_junk(source, &mut rng);
        // Should contain at least some junk code markers
        assert!(out.len() > source.len());
    }
}
