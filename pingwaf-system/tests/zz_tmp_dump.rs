#[test]
fn dump() {
    let snapshot = pingwaf_system::memory_snapshot();
    println!("{}", serde_json::to_string_pretty(&snapshot).unwrap());
}
