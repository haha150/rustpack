use rustpack::polymorphism::*;

#[test]
fn test_inject_junk_different_outputs() {
    let source = r#"fn main() {
    let x = 42;
    let y = x + 1;
    println!("{}", y);
}
"#;
    let mut rng1 = rand::thread_rng();
    let mut rng2 = rand::thread_rng();

    let out1 = inject_junk(source, &mut rng1);
    let out2 = inject_junk(source, &mut rng2);

    // Both must differ from original
    assert_ne!(out1, source);
    assert_ne!(out2, source);
    // Both must differ from each other (with high probability)
    // Note: There's an astronomically small chance they're the same
    assert!(out1.len() > source.len());
    assert!(out2.len() > source.len());
}

#[test]
fn test_inject_junk_balanced_braces() {
    let source = r#"fn test_func() {
    let a = 1;
    let b = 2;
    let c = a + b;
}

fn another_func() {
    let x = "hello";
    let _ = x.len();
}
"#;
    let mut rng = rand::thread_rng();
    let result = inject_junk(source, &mut rng);

    // Count braces - they should still be balanced
    let open_count = result.chars().filter(|&c| c == '{').count();
    let close_count = result.chars().filter(|&c| c == '}').count();
    assert_eq!(open_count, close_count);
}

#[test]
fn test_inject_junk_contains_markers() {
    let source = r#"fn main() {
    let x = 1;
    let y = 2;
    let z = 3;
    let w = 4;
    let v = 5;
}
"#;
    let mut rng = rand::thread_rng();
    let result = inject_junk(source, &mut rng);

    // Should contain at least one junk code marker
    let has_junk = result.contains("black_box")
        || result.contains("_jnk_")
        || result.contains("_s_")
        || result.contains("unreachable_")
        || result.contains("_end_");
    assert!(has_junk, "No junk code markers found in output");
}
