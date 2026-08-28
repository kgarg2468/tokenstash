//! The CLI's dependency on tokenstash-core carries an explicit `version` (required to publish);
//! it must track the workspace version or a published CLI would pull an older core from crates.io.
#[test]
fn core_dependency_version_matches_workspace() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    let dep = &manifest["dependencies"]["tokenstash-core"]["version"];
    assert_eq!(dep.as_str().unwrap(), env!("CARGO_PKG_VERSION"), "bump crates/cli/Cargo.toml tokenstash-core.version with the workspace version");
}
