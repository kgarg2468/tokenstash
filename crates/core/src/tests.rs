#![cfg(test)]
use crate::*;
use secrecy::SecretString;
use std::path::PathBuf;

/// Tests that point TOKENSTASH_HOME at a temp dir mutate process-global state; the test
/// harness runs tests in parallel threads, so those tests must not overlap.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

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
    // a symlinked .gitignore is refused, and the symlink target is untouched
    #[cfg(unix)]
    {
        let target = dir.join("elsewhere.txt");
        std::fs::write(&target, "keep me\n").unwrap();
        std::fs::remove_file(dir.join(".gitignore")).unwrap();
        std::os::unix::fs::symlink(&target, dir.join(".gitignore")).unwrap();
        assert!(envfile::ensure_gitignore(&sub, ".env.local").is_err());
        assert!(envfile::write(&sub, ".env.local", "K2", &SecretString::from("vvvvvvvv".to_string())).is_err(), "injection must fail when .gitignore cannot be enforced");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me\n");
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
fn redactor_handles_short_values_and_unicode() {
    // short values are redacted where they stand alone, not inside other words
    let r = redact::Redactor::new().with(&SecretString::from("ab".to_string()));
    assert_eq!(r.redact("token ab rejected"), "token [redacted] rejected");
    assert_eq!(r.redact("(ab)"), "([redacted])");
    assert_eq!(r.redact("cabbage about"), "cabbage about");
    assert_eq!(r.redact("ab"), "[redacted]");
    // multibyte values must not panic in mask()
    assert_eq!(redact::mask(&SecretString::from("ключ-секрет-значение".to_string())), "клю…ие");
    let r = redact::Redactor::new().with(&SecretString::from("ключ".to_string()));
    assert_eq!(r.redact("got ключ back"), "got [redacted] back");
}

#[test]
fn envfile_round_trips_adversarial_values() {
    let dir = tmp("envfile-rt");
    let cases = [
        "plain", "with space", "has#hash", "has\"quote", "back\\slash", "dollar$sign", "back`tick",
        "single'quote", "=leading-eq", "trailing-eq=", " padded ", "uni-ключ", "multi\nline", "",
    ];
    for (i, v) in cases.iter().enumerate() {
        let name = format!("K{i}");
        envfile::write(&dir, ".env.local", &name, &SecretString::from(v.to_string())).unwrap();
    }
    let s = std::fs::read_to_string(dir.join(".env.local")).unwrap();
    for (i, v) in cases.iter().enumerate() {
        if v.contains('\n') { continue; } // newlines are not representable in a one-line grammar
        let line = s.lines().find(|l| l.starts_with(&format!("K{i}="))).unwrap_or_else(|| panic!("missing K{i}"));
        let (k, parsed) = envfile::parse_line(line).unwrap();
        assert_eq!(k, format!("K{i}"));
        assert_eq!(&parsed, v, "round trip failed for {v:?} (line: {line})");
    }
    assert!(!s.contains("export "), "we never emit export");
}

#[test]
fn find_task_prefix_rules() {
    let dir = tmp("find-task");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let mk = |id: &str| db::Task {
        id: id.into(), kind: db::TaskKind::Secret, project: "/p".into(), agent: "t".into(), name: Some("X".into()),
        identity: "default".into(), title: "x".into(), why: None, url: None, steps: vec![], expects: "secret".into(),
        pattern: None, names: vec![], status: db::TaskStatus::Pending, created: now(), deadline: now(), answered_at: None, note: None,
    };
    db.insert_task(&mk("t_abc111")).unwrap();
    db.insert_task(&mk("t_abc222")).unwrap();
    db.insert_task(&mk("a_zzz999")).unwrap();
    assert_eq!(db.find_task("t_abc111").unwrap().unwrap().id, "t_abc111");
    assert_eq!(db.find_task("abc111").unwrap().unwrap().id, "t_abc111");
    assert_eq!(db.find_task("zzz").unwrap().unwrap().id, "a_zzz999");
    assert!(db.find_task("abc").is_err(), "ambiguous prefix must error");
    assert!(db.find_task("").is_err(), "empty must error");
    assert!(db.find_task("%").is_err(), "wildcards must error");
    assert!(db.find_task("nope").unwrap().is_none());
}

#[test]
fn trust_roots_are_canonical() {
    let dir = tmp("trust-canon");
    let root = dir.join("code"); std::fs::create_dir_all(root.join("proj")).unwrap();
    let outside = dir.join("outside"); std::fs::create_dir_all(&outside).unwrap();
    let cfg = Config { trust_roots: vec![root.clone()], ..Default::default() };
    // inside via a clean path
    assert!(trust::inside_roots(&root.join("proj"), &cfg));
    // escapes the root through `..`
    assert!(!trust::inside_roots(&root.join("proj/../../outside"), &cfg));
    // symlink inside the root pointing outside
    #[cfg(unix)]
    {
        let link = root.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(!trust::inside_roots(&link, &cfg), "symlink escaping the root must not be trusted");
    }
    // nonexistent paths are never trusted
    assert!(!trust::inside_roots(&root.join("does-not-exist"), &cfg));
}

#[test]
fn require_approval_gates_even_hits() {
    let _env = env_lock();
    let home = tmp("req-approval-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("req-approval-proj").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_x".to_string())).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "GROQ_API_KEY".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false }).unwrap();
    // normal hit inside a trust root: silent
    let out = need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
    // same hit from untrusted input: must produce an approval task instead
    let out = need::need(&ctx, &proj, "run", &["GROQ_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), other => panic!("expected approval, got {other:?}") };
    assert!(tid.starts_with("a_"));
    // approval injects; but a later program-derived request must ask again — persisted
    // approval never authorizes a fresh untrusted request
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), true).unwrap();
    assert!(envfile::has(&proj, ".env.local", "GROQ_API_KEY"));
    let out = need::need(&ctx, &proj, "run", &["GROQ_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "require_approval must ask every time");
    // ordinary requests in the trusted project stay silent
    let out = need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
}

#[test]
fn file_stash_is_atomic_and_locked() {
    let _env = env_lock();
    let home = tmp("stash-atomic");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let cfg = Config::default();
    let st = stash::open(&cfg).unwrap();
    st.set("A@default", &SecretString::from("valuevalue".to_string())).unwrap();
    let path = home.join("insecure-stash.json");
    // corrupt file is an error, not silently emptied
    std::fs::write(&path, "{not json").unwrap();
    assert!(st.get("A@default").is_err());
    assert!(st.set("B@default", &SecretString::from("bbbbbbbb".to_string())).is_err(), "must not overwrite a corrupt stash");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json", "corrupt content preserved for recovery");
    std::fs::write(&path, "{}").unwrap();
    // symlinked destination is refused
    let target = home.join("elsewhere.json");
    std::fs::write(&target, "{}").unwrap();
    std::fs::remove_file(&path).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(st.set("C@default", &SecretString::from("cccccccc".to_string())).is_err(), "must not write through a symlink");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}", "symlink target untouched");
        std::fs::remove_file(&path).unwrap();
    }
    // concurrent writers (separate handles, as two processes would have) do not lose
    // each other's updates
    let cfg2 = cfg.clone();
    let h = std::thread::spawn(move || {
        let st2 = stash::open(&cfg2).unwrap();
        for i in 0..25 { st2.set(&format!("T{i}@default"), &SecretString::from("threadval".to_string())).unwrap(); }
    });
    for i in 0..25 { st.set(&format!("M{i}@default"), &SecretString::from("mainvalue".to_string())).unwrap(); }
    h.join().unwrap();
    for i in 0..25 {
        assert!(st.get(&format!("T{i}@default")).unwrap().is_some(), "lost T{i}");
        assert!(st.get(&format!("M{i}@default")).unwrap().is_some(), "lost M{i}");
    }
    // no stray temp files. The advisory lock file persists by design (an OS lock is held on
    // an open handle; deleting the file would race other holders) and must be empty + 0600.
    let leftovers: Vec<_> = std::fs::read_dir(&home).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.contains(".tmp")).collect();
    assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    let lock = home.join("insecure-stash.lock");
    assert_eq!(std::fs::metadata(&lock).unwrap().len(), 0, "lock file must not carry data");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn need_end_to_end_with_file_stash() {
    let _env = env_lock();
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

#[test]
fn text_answers_that_look_like_secrets_are_refused() {
    use validate::looks_like_secret;
    assert!(looks_like_secret("sk-abcdefghijklmnopqrstuvwxyz012345"));
    assert!(looks_like_secret("re_123456789_ABCDEFGHIJKLMNOPQRSTUV"));
    assert!(looks_like_secret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123"));
    assert!(looks_like_secret("postgres://user:pass@db.example.com/app"));
    assert!(!looks_like_secret("us-east-1"));
    assert!(!looks_like_secret("yes, the DNS record is live now"));
    assert!(!looks_like_secret("project id is my-app-prod"));

    let home = tmp("human-refuse");
    let db = Db::open(&home.join("t.db")).unwrap();
    let cfg = Config::default();
    let st = stash::FileStash::new().unwrap(); // never touched by this test
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &st };
    let t = tasks::create_human_task(&ctx, &home, "t", tasks::HumanRequest { title: "which region?".into(), why: None, url: None, steps: vec![], expects: "text".into() }).unwrap();
    assert!(tasks::answer_human(&ctx, &t, Some("sk-abcdefghijklmnopqrstuvwxyz012345")).is_err());
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Pending, "refused answer must not close the task");
    tasks::answer_human(&ctx, &t, Some("us-east-1")).unwrap();
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Answered);
}

#[test]
fn answering_a_secret_marks_the_task_before_injection() {
    let _env = env_lock();
    let home = tmp("answer-tx-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("answer-tx-proj").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    let out = need::need(&ctx, &proj, "t", &["RESEND_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), _ => unreachable!() };
    let task = db.get_task(&tid).unwrap().unwrap();
    // make injection fail: the env file path is a symlink → refused
    std::os::unix::fs::symlink(proj.join("elsewhere"), proj.join(".env.local")).unwrap();
    let r = tasks::answer_secret(&ctx, &task, SecretString::from("re_validvalue_123456".to_string()), true);
    assert!(r.is_err(), "injection through a symlink must fail");
    // ...but the value is stored and the task is answered, so nothing is asked twice
    assert!(stash.get("RESEND_API_KEY@default").unwrap().is_some());
    assert_eq!(db.get_task(&tid).unwrap().unwrap().status, db::TaskStatus::Answered);
    assert!(db.get_secret("RESEND_API_KEY", "default").unwrap().is_some());
    // a blocking wait must not report Injected while the file is still unwritable...
    let blocking = need::NeedOpts { blocking: true, timeout: std::time::Duration::from_millis(200), ..Default::default() };
    let r = need::need(&ctx, &proj, "t", &["RESEND_API_KEY".to_string()], &blocking);
    assert!(r.is_err(), "must surface the injection failure, not claim success");
    // ...and once the obstacle is gone, the next call injects from the stash without asking
    std::fs::remove_file(proj.join(".env.local")).unwrap();
    let out = need::need(&ctx, &proj, "t", &["RESEND_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
    assert!(envfile::has(&proj, ".env.local", "RESEND_API_KEY"));
}

#[test]
fn same_name_different_identities_get_separate_tasks() {
    let _env = env_lock();
    let home = tmp("ident-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("ident-proj").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    let name = vec!["OPENAI_API_KEY".to_string()];
    let work = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("work".into()), ..Default::default() }).unwrap();
    let personal = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("personal".into()), ..Default::default() }).unwrap();
    let (tw, tp) = match (&work[0], &personal[0]) {
        (need::Outcome::Pending { task_id: a, .. }, need::Outcome::Pending { task_id: b, .. }) => (a.clone(), b.clone()),
        other => panic!("expected two pending tasks, got {other:?}"),
    };
    assert_ne!(tw, tp, "different identities must not share a task");
    assert_eq!(db.get_task(&tw).unwrap().unwrap().identity, "work");
    assert_eq!(db.get_task(&tp).unwrap().unwrap().identity, "personal");
    // answering the work task stores under @work only
    tasks::answer_secret(&ctx, &db.get_task(&tw).unwrap().unwrap(), SecretString::from("sk-workworkwork123".to_string()), true).unwrap();
    assert!(stash.get("OPENAI_API_KEY@work").unwrap().is_some());
    assert!(stash.get("OPENAI_API_KEY@personal").unwrap().is_none());
    assert_eq!(db.get_task(&tp).unwrap().unwrap().status, db::TaskStatus::Pending, "personal task untouched");
    // a repeat request for the same identity reuses its open task; denial is per identity too
    let again = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("personal".into()), ..Default::default() }).unwrap();
    assert!(matches!(&again[0], need::Outcome::Pending { task_id, .. } if *task_id == tp));
    tasks::deny(&ctx, &db.get_task(&tp).unwrap().unwrap(), None).unwrap();
    let denied = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("personal".into()), ..Default::default() }).unwrap();
    assert!(matches!(denied[0], need::Outcome::Denied { .. }));
    let work_hit = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("work".into()), ..Default::default() }).unwrap();
    assert!(matches!(work_hit[0], need::Outcome::Injected { .. }), "work identity unaffected by personal denial");
}

#[test]
fn tracked_env_file_is_refused_until_untracked() {
    let dir = tmp("tracked-env");
    let git = |args: &[&str]| {
        let st = std::process::Command::new("git").arg("-C").arg(&dir).args(args)
            .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@t").env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
        assert!(st.success(), "git {args:?} failed");
    };
    git(&["init", "-q", "."]);
    // the classic mistake: the env file was committed before anyone thought about it
    std::fs::write(dir.join(".env.local"), "OLD=1\n").unwrap();
    git(&["add", ".env.local"]);
    git(&["commit", "-q", "-m", "oops"]);
    assert!(envfile::is_git_tracked(&dir, &dir.join(".env.local")));
    let err = envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("git rm --cached"), "must tell the user how to fix it: {err}");
    assert_eq!(std::fs::read_to_string(dir.join(".env.local")).unwrap(), "OLD=1\n", "tracked file untouched");
    // after untracking, injection proceeds and the ignore rule is added
    git(&["rm", "-q", "--cached", ".env.local"]);
    assert!(!envfile::is_git_tracked(&dir, &dir.join(".env.local")));
    envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(envfile::has(&dir, ".env.local", "K"));
    assert!(std::fs::read_to_string(dir.join(".gitignore")).unwrap().lines().any(|l| l == ".env.local"));
}

#[test]
fn gitignore_coverage_is_glob_matched_not_assumed() {
    use envfile::ignore_line_covers as c;
    assert!(c(".env.local", ".env.local"));
    assert!(c("/.env.local", ".env.local"));
    assert!(c(".env*", ".env.local"));
    assert!(c("*.local", ".env.local"));
    assert!(c(".env.*", ".env.local"));
    assert!(c("*", ".env.local"));
    assert!(!c(".env*", "credentials.txt"), "pattern must actually match the configured name");
    assert!(!c("*.local", "secrets.env"));
    assert!(!c("!.env.local", ".env.local"), "negation is not coverage");
    assert!(!c(".env.local/", ".env.local"), "directory rule is not coverage");
    assert!(!c("config/.env.local", ".env.local"), "path-anchored rules are not evaluated");
    assert!(!c("# .env.local", ".env.local"));
    assert!(c(".env.?ocal", ".env.local"));
    // end to end with a non-default name and a misleading existing rule
    let dir = tmp("gi-glob");
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".gitignore"), ".env*\n").unwrap();
    envfile::write(&dir, "credentials.txt", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    let gi = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert!(gi.lines().any(|l| l == "credentials.txt"), "explicit rule must be appended: {gi}");
}

#[test]
fn approvals_follow_the_resolved_project_not_the_symlink() {
    let _env = env_lock();
    let home = tmp("approval-link-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let base = tmp("approval-link");
    let a = base.join("a"); let b = base.join("b"); std::fs::create_dir_all(&a).unwrap(); std::fs::create_dir_all(&b).unwrap();
    let link = base.join("current");
    std::os::unix::fs::symlink(&a, &link).unwrap();
    let cfg = Config { trust_roots: vec![], ..Default::default() }; // nothing trusted: every project needs approval
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaa".to_string())).unwrap();
    // approve via the symlink while it points at a
    let out = need::need(&ctx, &link, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), true).unwrap();
    assert!(envfile::has(&a, ".env.local", "OPENAI_API_KEY"));
    // retarget the symlink at b: the approval must not carry over
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&b, &link).unwrap();
    let out = need::need(&ctx, &link, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "retargeted symlink must need its own approval");
    assert!(!envfile::has(&b, ".env.local", "OPENAI_API_KEY"));
}

#[test]
fn approval_injects_the_requested_identity() {
    let _env = env_lock();
    let home = tmp("approval-ident-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("approval-ident-proj").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![], ..Default::default() }; // untrusted → approval needed
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    stash.set("OPENAI_API_KEY@default", &SecretString::from("sk-defaultdefault".to_string())).unwrap();
    stash.set("OPENAI_API_KEY@work", &SecretString::from("sk-workworkwork1".to_string())).unwrap();
    let opts = need::NeedOpts { identity: Some("work".into()), ..Default::default() };
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &opts).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, identity, .. } => { assert_eq!(identity, "work"); task_id.clone() } o => panic!("{o:?}") };
    let t = db.get_task(&tid).unwrap().unwrap();
    assert!(t.names.contains(&"OPENAI_API_KEY@work".to_string()), "approval must record the identity: {:?}", t.names);
    tasks::answer_approval(&ctx, &t, true).unwrap();
    let env = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(env.contains("OPENAI_API_KEY=sk-workworkwork1"), "must inject the work identity, got: {env}");
    assert!(!env.contains("sk-defaultdefault"));
    // the waiter injects the requested identity even when the file already holds another
    // identity's value under the same name
    std::fs::write(proj.join(".env.local"), "OPENAI_API_KEY=sk-defaultdefault\n").unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts { identity: Some("work".into()), blocking: true, timeout: std::time::Duration::from_millis(200), ..Default::default() }).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { identity, .. } if identity == "work"), "{:?}", out[0]);
    assert!(std::fs::read_to_string(proj.join(".env.local")).unwrap().contains("sk-workworkwork1"));
}

#[test]
fn gitignore_last_match_wins() {
    use envfile::gitignore_covers as g;
    assert!(g(".env.local\n", ".env.local"));
    assert!(!g(".env.local\n!.env.local\n", ".env.local"), "later negation re-includes");
    assert!(g(".env.local\n!.env.local\n.env.local\n", ".env.local"), "later positive wins again");
    assert!(!g("!.env.local\n", ".env.local"));
    assert!(g(".env*\n!.env.example\n", ".env.local"), "negation of a different name is irrelevant");
    assert!(!g(".env*\n!.env.*\n", ".env.local"), "negated glob un-ignores");
    assert!(g("secrets/\n.env.local\n", ".env.local"), "directory rules are skipped, not treated as negation");
    assert!(!g(" .env.local\n", ".env.local"), "leading whitespace is part of a git pattern");
    assert!(g(".env.local   \n", ".env.local"), "trailing whitespace is ignored by git");
    // end to end: a negated file gets an explicit trailing rule, which wins
    let dir = tmp("gi-neg");
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".gitignore"), ".env.local\n!.env.local\n").unwrap();
    envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    let gi = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert!(g(&gi, ".env.local"), "after write, the file must be ignored: {gi}");
    assert_eq!(gi.lines().last(), Some(".env.local"));
}

#[test]
fn secret_is_not_written_when_ignore_protection_fails() {
    let dir = tmp("gi-fail");
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    let target = dir.join("elsewhere.txt");
    std::fs::write(&target, "keep\n").unwrap();
    std::os::unix::fs::symlink(&target, dir.join(".gitignore")).unwrap();
    assert!(envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).is_err());
    assert!(!dir.join(".env.local").exists(), "secret must not land on disk without confirmed ignore protection");
}

#[test]
fn approval_is_final_even_if_injection_fails() {
    let _env = env_lock();
    let home = tmp("approval-final-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("approval-final-proj").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    stash.set("A_KEY@default", &SecretString::from("aaaaaaaaaa".to_string())).unwrap();
    stash.set("B_KEY@default", &SecretString::from("bbbbbbbbbb".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["A_KEY".to_string(), "B_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    std::os::unix::fs::symlink(proj.join("nowhere"), proj.join(".env.local")).unwrap();
    let r = tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), true);
    assert!(r.is_err(), "injection failure must be surfaced");
    assert_eq!(db.get_task(&tid).unwrap().unwrap().status, db::TaskStatus::Answered);
    assert!(db.is_approved(&proj.to_string_lossy(), "A_KEY").unwrap());
    std::fs::remove_file(proj.join(".env.local")).unwrap();
    let out = need::need(&ctx, &proj, "t", &["A_KEY".to_string(), "B_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(out.iter().all(|o| matches!(o, need::Outcome::Injected { .. })), "{out:?}");
}

#[test]
fn program_derived_approvals_do_not_merge() {
    let _env = env_lock();
    let home = tmp("approval-merge-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("approval-merge-proj").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    stash.set("A_KEY@default", &SecretString::from("aaaaaaaaaa".to_string())).unwrap();
    stash.set("B_KEY@default", &SecretString::from("bbbbbbbbbb".to_string())).unwrap();
    let ra = need::NeedOpts { require_approval: true, ..Default::default() };
    let a = need::need(&ctx, &proj, "run", &["A_KEY".to_string()], &ra).unwrap();
    let b = need::need(&ctx, &proj, "run", &["B_KEY".to_string()], &ra).unwrap();
    let (ta, tb) = match (&a[0], &b[0]) {
        (need::Outcome::Pending { task_id: x, .. }, need::Outcome::Pending { task_id: y, .. }) => (x.clone(), y.clone()),
        o => panic!("{o:?}"),
    };
    assert_ne!(ta, tb, "two program-derived requests must not share an approval task");
    tasks::answer_approval(&ctx, &db.get_task(&ta).unwrap().unwrap(), true).unwrap();
    assert!(envfile::has(&proj, ".env.local", "A_KEY"));
    assert!(!envfile::has(&proj, ".env.local", "B_KEY"), "B must wait for its own approval");
    assert_eq!(db.get_task(&tb).unwrap().unwrap().status, db::TaskStatus::Pending);
    let c = need::need(&ctx, &proj, "t", &["A_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(c[0], need::Outcome::Injected { .. }));
}

#[test]
fn wait_does_not_file_duplicate_program_approvals() {
    let _env = env_lock();
    let home = tmp("wait-dup-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("wait-dup-proj").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref() };
    stash.set("A_KEY@default", &SecretString::from("aaaaaaaaaa".to_string())).unwrap();
    let ra = need::NeedOpts { require_approval: true, ..Default::default() };
    let mut out = need::need(&ctx, &proj, "run", &["A_KEY".to_string()], &ra).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    // approve from "another thread" shortly after the wait begins
    let db2 = Db::open(&home.join("t.db")).unwrap();
    let cfg2 = cfg.clone(); let tid2 = tid.clone(); let proj2 = proj.clone();
    let h = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let st = stash::open(&cfg2).unwrap();
        let c = tasks::Ctx { cfg: &cfg2, db: &db2, stash: st.as_ref() };
        tasks::answer_approval(&c, &db2.get_task(&tid2).unwrap().unwrap(), true).unwrap();
        let _ = proj2;
    });
    need::wait(&ctx, &proj, &mut out, std::time::Duration::from_secs(5)).unwrap();
    h.join().unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{:?}", out[0]);
    let open: Vec<_> = db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap();
    assert!(open.is_empty(), "waiting must not file a second approval task: {open:?}");
}
