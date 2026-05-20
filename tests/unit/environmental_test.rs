use rustpack::environmental::*;

#[test]
fn test_kill_date_past() {
    let snippet = kill_date_check_snippet("2020-01-01").unwrap();
    // Should contain a Unix timestamp that's in the past
    assert!(snippet.contains("Duration::from_secs("));
    assert!(snippet.contains("std::process::exit(0)"));
    // The timestamp for 2020-01-01 23:59:59 UTC is 1577923199
    assert!(snippet.contains("1577923199"));
}

#[test]
fn test_kill_date_future() {
    let snippet = kill_date_check_snippet("2030-12-31").unwrap();
    assert!(snippet.contains("Duration::from_secs("));
    // Should be a large timestamp
    assert!(snippet.contains("std::process::exit(0)"));
}

#[test]
fn test_kill_date_invalid() {
    let result = kill_date_check_snippet("not-a-date");
    assert!(result.is_err());
}

#[test]
fn test_hostname_key_snippet_contains_hash() {
    let snippet = hostname_key_snippet("WORKSTATION01");
    // Should contain a 64-char hex SHA-256 hash
    assert!(snippet.contains("std::process::exit(0)"));

    // Extract the hash from the snippet
    let hash_start = snippet.find("!= \"").unwrap() + 4;
    let hash_end = snippet[hash_start..].find('"').unwrap() + hash_start;
    let hash = &snippet[hash_start..hash_end];

    // Verify it's a valid 64-char hex string
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_domain_key_snippet() {
    let snippet = domain_key_snippet("CONTOSO.COM");
    assert!(snippet.contains("CONTOSO.COM"));
    assert!(snippet.contains("NetGetJoinInformation"));
    assert!(snippet.contains("std::process::exit(0)"));
}

#[test]
fn test_sandbox_domain_joined() {
    let snippet = sandbox_check_snippet("DomainJoined");
    assert!(snippet.contains("NetGetJoinInformation"));
    assert!(snippet.contains("NetSetupDomainName"));
}

#[test]
fn test_sandbox_threshold() {
    let snippet = sandbox_check_snippet("Threshold");
    assert!(snippet.contains("dwNumberOfProcessors"));
    assert!(snippet.contains("vmtoolsd"));
    assert!(snippet.contains("vboxservice"));
}
