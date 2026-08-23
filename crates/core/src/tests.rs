#![cfg(test)]
use crate::*;
use secrecy::SecretString;
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn registry_is_sane() {
    assert!(registry::count() >= 40);
    for p in registry::all() {
        assert!(p.url.starts_with("https://"), "{} url", p.name);
        if let Some(pat) = &p.pattern { regex::Regex::new(pat).unwrap_or_else(|_| panic!("bad pattern for {}", p.name)); }
        if let Some(pat) = &p.sensitive_pattern { regex::Regex::new(pat).unwrap(); }
        if let Some(c) = &p.check { assert!(c.url.starts_with("https://"), "{} check url", p.name); }
        assert!(p.name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'), "{} name", p.name);
    }
}

#[test]
fn envfile_upserts_and_quotes_and_restricts() {
    let dir = tmp("envfile");
    let v1 = SecretString::from("plain-value".to_string());
    let v2 = SecretString::from("has space # and \"quotes\"".to_string());
    envfile::write(&dir, ".env.local", "A_KEY", &v1).unwrap();
    envfile::write(&dir, ".env.local", "B_KEY", &v2).unwrap();
    envfile::write(&dir, ".env.local", "A_KEY", &SecretString::from("second".to_string())).unwrap();
    let s = std::fs::read_to_string(dir.join(".env.local")).unwrap();
    assert_eq!(s.lines().filter(|l| l.starts_with("A_KEY=")).count(), 1);
    assert!(s.contains("A_KEY=second"));
    assert!(s.contains("B_KEY=\"has space # and \\\"quotes\\\"\""));
    assert!(envfile::has(&dir, ".env.local", "B_KEY"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join(".env.local")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn gitignore_is_enforced_in_repos() {
    let dir = tmp("gitignore");
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".gitignore"), "node_modules\n").unwrap();
    let sub = dir.join("packages/app");
    std::fs::create_dir_all(&sub).unwrap();
    envfile::write(&sub, ".env.local", "K", &SecretString::from("v".to_string())).unwrap();
    let gi = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert!(gi.lines().any(|l| l == ".env.local"));
    // idempotent
    assert!(!envfile::ensure_gitignore(&sub, ".env.local").unwrap());
    // already covered by a glob
    std::fs::write(dir.join(".gitignore"), ".env*\n").unwrap();
    assert!(!envfile::ensure_gitignore(&sub, ".env.local").unwrap());
}

#[test]
fn tracked_env_file_is_untracked_before_write() {
    if std::process::Command::new("git").arg("--version").output().is_err() {
        return; // no git in this environment
    }
    let dir = tmp("tracked-env");
    let git = |args: &[&str]| {
        std::process::Command::new("git").args(args).current_dir(&dir).output().unwrap();
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "t@t"]);
    git(&["config", "user.name", "t"]);
    std::fs::write(dir.join(".env.local"), "EXISTING=1\n").unwrap();
    git(&["add", ".env.local"]);
    git(&["commit", "-qm", "tracked env file"]);
    let tracked = || {
        String::from_utf8(
            std::process::Command::new("git").args(["ls-files", "--", ".env.local"]).current_dir(&dir).output().unwrap().stdout,
        ).unwrap()
    };
    assert!(!tracked().trim().is_empty(), "precondition: file is tracked");
    envfile::write(&dir, ".env.local", "K", &SecretString::from("v".to_string())).unwrap();
    assert!(tracked().trim().is_empty(), "env file must be untracked before a secret is written");
    let s = std::fs::read_to_string(dir.join(".env.local")).unwrap();
    assert!(s.contains("K=v"));
}

#[test]
fn symlinked_env_file_is_refused() {
    #[cfg(unix)]
    {
        let dir = tmp("symlink-env");
        let target = tmp("symlink-target");
        std::fs::write(target.join("real.env"), "EXISTING=1\n").unwrap();
        std::os::unix::fs::symlink(target.join("real.env"), dir.join(".env.local")).unwrap();
        let err = envfile::write(&dir, ".env.local", "K", &SecretString::from("v".to_string())).unwrap_err();
        assert!(err.to_string().contains("symlink"), "must refuse: {err}");
        let s = std::fs::read_to_string(target.join("real.env")).unwrap();
        assert!(!s.contains("K=v"), "secret must not reach the symlink target");

        // a symlinked PARENT directory must be refused too
        std::fs::create_dir_all(dir.join("realdir")).unwrap();
        std::os::unix::fs::symlink(dir.join("realdir"), dir.join("linkdir")).unwrap();
        let err = envfile::write(&dir, "linkdir/.env.local", "K", &SecretString::from("v".to_string())).unwrap_err();
        assert!(err.to_string().contains("symlink"), "must refuse parent symlink: {err}");
        assert!(!dir.join("realdir/.env.local").exists(), "secret must not reach the redirected directory");

        // a plain nested path still works
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        envfile::write(&dir, "sub/.env.local", "K", &SecretString::from("v".to_string())).unwrap();
        assert!(std::fs::read_to_string(dir.join("sub/.env.local")).unwrap().contains("K=v"));
    }
}

#[test]
fn trust_gate_logic() {
    let dir = tmp("trust");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let root = dir.join("code");
    std::fs::create_dir_all(root.join("proj")).unwrap();
    let cfg = Config { trust_roots: vec![root.clone()], ..Default::default() };
    let inside = root.join("proj").canonicalize().unwrap();
    let outside = dir.join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    let outside = outside.canonicalize().unwrap();

    assert_eq!(trust::gate(&db, &cfg, &inside, "OPENAI_API_KEY", false).unwrap(), trust::Gate::Open);
    assert!(matches!(trust::gate(&db, &cfg, &inside, "AWS_SECRET_ACCESS_KEY", true).unwrap(), trust::Gate::NeedsApproval { reason: trust::GateReason::Sensitive }));
    assert!(matches!(trust::gate(&db, &cfg, &outside, "OPENAI_API_KEY", false).unwrap(), trust::Gate::NeedsApproval { reason: trust::GateReason::OutsideTrustRoots }));
    db.approve(&outside.to_string_lossy(), "*").unwrap();
    assert_eq!(trust::gate(&db, &cfg, &outside, "OPENAI_API_KEY", false).unwrap(), trust::Gate::Open);
    db.approve(&inside.to_string_lossy(), "AWS_SECRET_ACCESS_KEY").unwrap();
    assert_eq!(trust::gate(&db, &cfg, &inside, "AWS_SECRET_ACCESS_KEY", true).unwrap(), trust::Gate::Open);
}

#[test]
fn redactor_scrubs_values() {
    let r = redact::Redactor::new().with(&SecretString::from("sk-super-secret-value".to_string()));
    assert_eq!(r.redact("error: sk-super-secret-value rejected"), "error: [redacted] rejected");
    assert_eq!(redact::mask(&SecretString::from("sk-1234567890".to_string())), "sk-…90");
    assert_eq!(redact::mask(&SecretString::from("short".to_string())), "••••");
}

#[test]
fn need_end_to_end_with_file_stash() {
    let home = tmp("need-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("need-proj");
    let proj = proj.canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    let names = vec!["OPENAI_API_KEY".to_string(), "AUTH_SECRET".to_string()];
    let out = need::need(&ctx, &proj, "test", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
    assert!(matches!(out[1], need::Outcome::Injected { generated: true, .. }));
    // answer
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), _ => unreachable!() };
    let t = db.get_task(&tid).unwrap().unwrap();
    let bad = tasks::answer_secret(&ctx, &t, SecretString::from("nope".to_string()), true);
    assert!(bad.is_err(), "pattern must reject");
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-LEAKCANARY-unit".to_string()), true).unwrap();
    let env = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(env.contains("OPENAI_API_KEY=sk-LEAKCANARY-unit"));
    // second call is a silent hit
    let out = need::need(&ctx, &proj, "test", &names[..1], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { generated: false, .. }));
    // deny memory
    let out = need::need(&ctx, &proj, "test", &["STRIPE_SECRET_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), _ => unreachable!() };
    tasks::deny(&ctx, &db.get_task(&tid).unwrap().unwrap(), None).unwrap();
    let out = need::need(&ctx, &proj, "test", &["STRIPE_SECRET_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Denied { .. }), "deny must be remembered");
    let out = need::need(&ctx, &proj, "test", &["STRIPE_SECRET_KEY".to_string()], &need::NeedOpts { force: true, ..Default::default() }).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "--force asks again");
    // nothing in the db
    let raw = std::fs::read(home.join("t.db")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("LEAKCANARY"), "value leaked into db");
}
