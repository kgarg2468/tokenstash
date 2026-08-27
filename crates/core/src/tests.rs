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

/// The human paired this key into this directory (what answering a pairing card records).
fn pair(db: &Db, proj: &std::path::Path, name: &str) {
    let ws = db.workspace_for(proj).unwrap();
    db.grant(&ws.id, name, "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
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
        if let Some(c) = &p.check {
            assert!(c.url.starts_with("https://"), "{} check url", p.name);
            assert!(matches!(c.method.as_str(), "GET" | "POST"), "{} check method {}", p.name, c.method);
            // An auth style validate::liveness does not understand falls into its
            // catch-all arm and sends the probe with no credential at all, which
            // makes the check silently meaningless. Typos must fail here instead.
            let known = c.auth == "bearer"
                || c.auth == "basic-user"
                || c.auth.strip_prefix("header:").is_some_and(|s| !s.is_empty())
                || c.auth.strip_prefix("prefix:").is_some_and(|s| !s.is_empty())
                || c.auth.strip_prefix("query:").is_some_and(|s| !s.is_empty());
            assert!(known, "{} unsupported check auth {:?}", p.name, c.auth);
            for s in &c.reject_status {
                assert!((400..600).contains(s), "{} reject_status {}", p.name, s);
                assert!(*s != 401, "{} reject_status {} is already implied", p.name, s);
            }
        }
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
    // A grant is (workspace, key, identity). Nothing is inferred from folders.
    let dir = tmp("trust");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let proj = dir.join("code/proj");
    std::fs::create_dir_all(&proj).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    let pairing = |g: &trust::Gate| matches!(g, trust::Gate::NeedsApproval { reason: trust::GateReason::Pairing });
    let sens = |g: &trust::Gate| matches!(g, trust::Gate::NeedsApproval { reason: trust::GateReason::Sensitive });
    let open = |g: &trust::Gate| matches!(g, trust::Gate::Open { .. });
    assert!(pairing(&trust::gate(&db, &ws, "OPENAI_API_KEY", "default", false, true).unwrap()));
    assert!(sens(&trust::gate(&db, &ws, "AWS_SECRET_ACCESS_KEY", "default", true, true).unwrap()));
    assert!(sens(&trust::gate(&db, &ws, "MY_INTERNAL_TOKEN", "default", false, false).unwrap()), "unregistered keys are per-key decisions");
    // an exact grant opens exactly that (key, identity)
    db.grant(&ws.id, "OPENAI_API_KEY", "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
    assert!(open(&trust::gate(&db, &ws, "OPENAI_API_KEY", "default", false, true).unwrap()));
    assert!(pairing(&trust::gate(&db, &ws, "OPENAI_API_KEY", "work", false, true).unwrap()), "another identity is another grant");
    assert!(pairing(&trust::gate(&db, &ws, "GROQ_API_KEY", "default", false, true).unwrap()));
    // a broad grant covers registry non-sensitive keys for its identity, never sensitive ones
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    assert!(open(&trust::gate(&db, &ws, "GROQ_API_KEY", "default", false, true).unwrap()));
    assert!(pairing(&trust::gate(&db, &ws, "GROQ_API_KEY", "work", false, true).unwrap()));
    assert!(sens(&trust::gate(&db, &ws, "AWS_SECRET_ACCESS_KEY", "default", true, true).unwrap()));
    assert!(sens(&trust::gate(&db, &ws, "MY_INTERNAL_TOKEN", "default", false, false).unwrap()));
    db.grant(&ws.id, "AWS_SECRET_ACCESS_KEY", "default", db::GRANT_KEY, db::GRANT_SENSITIVE).unwrap();
    assert!(open(&trust::gate(&db, &ws, "AWS_SECRET_ACCESS_KEY", "default", true, true).unwrap()));
    // another directory shares nothing
    let other = dir.join("code/other");
    std::fs::create_dir_all(&other).unwrap();
    let ws2 = db.workspace_for(&other).unwrap();
    assert_ne!(ws.id, ws2.id);
    assert!(pairing(&trust::gate(&db, &ws2, "OPENAI_API_KEY", "default", false, true).unwrap()));
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
fn workspace_identity_is_the_directory_not_the_path_string() {
    let dir = tmp("ws-ident");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let proj = dir.join("code/proj");
    std::fs::create_dir_all(&proj).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    // spellings of the same directory resolve to one workspace
    assert_eq!(db.workspace_for(&dir.join("code/./proj/../proj")).unwrap().id, ws.id);
    #[cfg(unix)]
    {
        let link = dir.join("link");
        std::os::unix::fs::symlink(&proj, &link).unwrap();
        assert_eq!(db.workspace_for(&link).unwrap().id, ws.id, "a symlink is the directory it points at");
    }
    // find never creates
    assert!(db.find_workspace(&dir.join("code/nothing-here")).unwrap().is_none());
    assert!(db.workspace_for(&dir.join("code/does-not-exist")).is_err());
    // the same path, re-created, is a different directory: grants do not carry over
    db.grant(&ws.id, "OPENAI_API_KEY", "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
    std::fs::remove_dir_all(&proj).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::create_dir_all(&proj).unwrap();
    let again = db.workspace_for(&proj).unwrap();
    assert_eq!(again.id, ws.id, "the record stays until a human pairs the new directory");
    assert!(!again.fingerprint_ok, "…but it is flagged, and no grant applies");
    assert!(matches!(trust::gate(&db, &again, "OPENAI_API_KEY", "default", false, true).unwrap(), trust::Gate::NeedsApproval { .. }));
    assert!(db.find_workspace(&proj).unwrap().is_none());
    // the human pairs the new directory: old grants go, a new record replaces the old
    let fresh = db.repair_workspace(&proj).unwrap();
    assert_ne!(fresh.id, ws.id);
    assert!(fresh.fingerprint_ok);
    assert!(db.grants_for(&ws.id).unwrap().is_empty(), "old grants revoked");
    assert!(db.grants_for(&fresh.id).unwrap().is_empty());
    // refused roots
    assert!(trust::refused_root(std::path::Path::new("/")).is_some());
    assert!(trust::refused_root(&dirs::home_dir().unwrap()).is_some());
    assert!(trust::refused_root(std::path::Path::new("/tmp")).is_some());
    assert!(trust::refused_root(&proj).is_none(), "a child of /tmp is fine");
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_x".to_string())).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "GROQ_API_KEY".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    // normal hit in a paired directory: silent
    pair(&db, &proj, "GROQ_API_KEY");
    let out = need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
    // same hit from untrusted input: must produce an approval task instead
    let out = need::need(&ctx, &proj, "run", &["GROQ_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), other => panic!("expected approval, got {other:?}") };
    assert!(tid.starts_with("a_"));
    // approval injects; but a later program-derived request must ask again — persisted
    // approval never authorizes a fresh untrusted request
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &st, probe: tasks::Probe::Off };
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaa".to_string())).unwrap();
    // approve via the symlink while it points at a
    let out = need::need(&ctx, &link, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set("OPENAI_API_KEY@default", &SecretString::from("sk-defaultdefault".to_string())).unwrap();
    stash.set("OPENAI_API_KEY@work", &SecretString::from("sk-workworkwork1".to_string())).unwrap();
    let opts = need::NeedOpts { identity: Some("work".into()), ..Default::default() };
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &opts).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, identity, .. } => { assert_eq!(identity, "work"); task_id.clone() } o => panic!("{o:?}") };
    let t = db.get_task(&tid).unwrap().unwrap();
    assert!(t.names.contains(&"OPENAI_API_KEY@work".to_string()), "approval must record the identity: {:?}", t.names);
    tasks::answer_approval(&ctx, &t, tasks::Decision::Allow, None).unwrap();
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set("A_KEY@default", &SecretString::from("aaaaaaaaaa".to_string())).unwrap();
    stash.set("B_KEY@default", &SecretString::from("bbbbbbbbbb".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["A_KEY".to_string(), "B_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    std::os::unix::fs::symlink(proj.join("nowhere"), proj.join(".env.local")).unwrap();
    let r = tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None);
    assert!(r.is_err(), "injection failure must be surfaced");
    assert_eq!(db.get_task(&tid).unwrap().unwrap().status, db::TaskStatus::Answered);
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.grant_source(&ws.id, "A_KEY", "default").unwrap().is_some());
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
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
    tasks::answer_approval(&ctx, &db.get_task(&ta).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    assert!(envfile::has(&proj, ".env.local", "A_KEY"));
    assert!(!envfile::has(&proj, ".env.local", "B_KEY"), "B must wait for its own approval");
    assert_eq!(db.get_task(&tb).unwrap().unwrap().status, db::TaskStatus::Pending);
    // the one-time approval is not a grant: an ordinary request pairs on its own
    let c = need::need(&ctx, &proj, "t", &["A_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(c[0], need::Outcome::Pending { .. }), "{c:?}");
    pair(&db, &proj, "A_KEY");
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
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
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
        let c = tasks::Ctx { cfg: &cfg2, db: &db2, stash: st.as_ref(), probe: tasks::Probe::Off };
        tasks::answer_approval(&c, &db2.get_task(&tid2).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
        let _ = proj2;
    });
    need::wait(&ctx, &proj, &mut out, std::time::Duration::from_secs(5)).unwrap();
    h.join().unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{:?}", out[0]);
    let open: Vec<_> = db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap();
    assert!(open.is_empty(), "waiting must not file a second approval task: {open:?}");
}

#[test]
fn nested_gitignore_reinclude_is_handled_via_git() {
    let dir = tmp("gi-nested");
    let git = |args: &[&str]| {
        let st = std::process::Command::new("git").arg("-C").arg(&dir).args(args)
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
        assert!(st.success(), "git {args:?}");
    };
    git(&["init", "-q", "."]);
    let sub = dir.join("apps/web");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(dir.join(".gitignore"), ".env.local\n").unwrap();
    std::fs::write(sub.join(".gitignore"), "!.env.local\n").unwrap();
    assert_eq!(envfile::git_check_ignore(&dir, &sub.join(".env.local")), Some(false));
    envfile::write(&sub, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert_eq!(envfile::git_check_ignore(&dir, &sub.join(".env.local")), Some(true), "must be effectively ignored after write");
    let nested = std::fs::read_to_string(sub.join(".gitignore")).unwrap();
    assert_eq!(nested.lines().last(), Some(".env.local"), "rule appended to the closest ignore file: {nested}");
}

/// `env_file` is configuration, not a trusted path. Every protection in this module
/// (gitignore coverage, the tracked-file check) is anchored on the project directory, so a
/// value that resolves outside it is a secret written with no protection at all.
#[test]
fn absolute_env_file_is_refused() {
    let dir = tmp("envfile-abs");
    let outside = tmp("envfile-abs-outside").join("ESCAPE-TARGET.env");
    let target = outside.to_string_lossy().to_string();
    let err = envfile::write(&dir, &target, "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("relative"), "must name the problem: {err}");
    assert!(!outside.exists(), "an absolute env_file must not write a secret outside the project");
    assert!(!envfile::has(&dir, &target, "K"));
}

#[test]
fn env_file_escaping_with_dotdot_is_refused() {
    let base = tmp("envfile-dotdot");
    let proj = base.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let err = envfile::write(&proj, "../ESCAPE-TARGET.env", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains(".."), "must name the problem: {err}");
    assert!(!base.join("ESCAPE-TARGET.env").exists(), "'..' must not write a secret outside the project");
}

#[test]
fn env_file_under_a_symlinked_parent_outside_the_project_is_refused() {
    let base = tmp("envfile-linked-parent");
    let proj = base.join("proj");
    let outside = base.join("outside");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, proj.join("linked")).unwrap();
    let err = envfile::write(&proj, "linked/.env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("outside the project"), "must name the problem: {err}");
    assert!(!outside.join(".env.local").exists(), "a symlinked parent must not route the secret out of the project");
    // ...while a genuine subdirectory of the project still works
    std::fs::create_dir_all(proj.join("config")).unwrap();
    envfile::write(&proj, "config/.env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(envfile::has(&proj, "config/.env.local", "K"));
}

#[test]
fn tracked_env_file_is_still_refused_when_project_path_is_a_symlink() {
    // macOS hands out /var/folders/... while the canonical path is /private/var/...; a
    // resolver that hands git a canonical path defeats the tracked-file check.
    let real = tmp("tracked-env-symlink-real");
    let link = std::env::temp_dir().join(format!("tokenstash-test-tracked-env-symlink-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let git = |args: &[&str]| {
        let st = std::process::Command::new("git").arg("-C").arg(&real).args(args)
            .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@t").env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
        assert!(st.success(), "git {args:?} failed");
    };
    git(&["init", "-q", "."]);
    std::fs::write(real.join(".env.local"), "OLD=1\n").unwrap();
    git(&["add", ".env.local"]);
    git(&["commit", "-q", "-m", "oops"]);
    let err = envfile::write(&link, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("git rm --cached"), "tracked file must be refused through a symlinked project path: {err}");
    assert_eq!(std::fs::read_to_string(real.join(".env.local")).unwrap(), "OLD=1\n");
    let _ = std::fs::remove_file(&link);
}

#[test]
fn env_file_with_leading_dot_slash_is_accepted() {
    let dir = tmp("envfile-curdir");
    std::process::Command::new("git").arg("-C").arg(&dir).args(["init", "-q", "."]).status().unwrap();
    let p = envfile::write(&dir, "./.env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(p.starts_with(&dir));
    assert!(envfile::has(&dir, "./.env.local", "K"));
}


#[test]
fn a_git_dir_in_a_shared_ancestor_never_becomes_the_project_root() {
    // /tmp-like: sticky, world-writable. A stray .git there must not capture children.
    let shared = tmp("shared-ancestor");
    std::fs::create_dir_all(shared.join(".git")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
    }
    let proj = shared.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    assert_eq!(envfile::owned_git_root(&proj).unwrap(), None, "sticky ancestor must not be a root");
    assert_eq!(envfile::git_root(&shared.join("proj")), Some(shared.clone()), "plain detection still sees it");
    assert_eq!(crate::project::canonical(&proj), proj.canonicalize().unwrap());
    // ...and the env file lands in the project, not the ancestor
    let written = envfile::write(&proj, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(written.starts_with(proj.canonicalize().unwrap()) || written.starts_with(&proj), "{}", written.display());
    assert!(!shared.join(".env.local").exists());
    assert!(!shared.join(".gitignore").exists(), "no ignore rule written into the shared ancestor");
    // a normal, user-owned repo still resolves as before
    let repo = tmp("owned-repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let sub = repo.join("a/b");
    std::fs::create_dir_all(&sub).unwrap();
    assert_eq!(envfile::git_root(&sub), Some(repo.clone()));
    assert_eq!(envfile::owned_git_root(&sub).unwrap(), Some(repo.clone()));
    // a tracked env file is still refused inside the shared ancestor: detection is not
    // suppressed, only adoption as a write root
    let _ = std::process::Command::new("git").arg("-C").arg(&shared).args(["init", "-q", "."]).status();
    std::fs::write(shared.join("proj/.env.local"), "OLD=1\n").unwrap();
    let _ = std::process::Command::new("git").arg("-C").arg(&shared).args(["add", "proj/.env.local"]).env("GIT_AUTHOR_NAME","t").env("GIT_AUTHOR_EMAIL","t@t").status();
    assert!(envfile::is_git_tracked(&proj, &proj.join(".env.local")));
    assert!(envfile::write(&proj, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).is_err());
}


#[test]
fn a_broad_grant_never_unlocks_sensitive_keys() {
    let dir = tmp("wildcard-sensitive");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let outside = dir.join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    let ws = db.workspace_for(&outside).unwrap();
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    assert!(matches!(trust::gate(&db, &ws, "OPENAI_API_KEY", "default", false, true).unwrap(), trust::Gate::Open { .. }));
    assert!(matches!(trust::gate(&db, &ws, "STRIPE_SECRET_KEY", "default", true, true).unwrap(), trust::Gate::NeedsApproval { reason: trust::GateReason::Sensitive }),
        "a broad grant must not silence a sensitive key");
    db.grant(&ws.id, "STRIPE_SECRET_KEY", "default", db::GRANT_KEY, db::GRANT_SENSITIVE).unwrap();
    assert!(matches!(trust::gate(&db, &ws, "STRIPE_SECRET_KEY", "default", true, true).unwrap(), trust::Gate::Open { .. }));
}

#[test]
fn a_run_shim_approval_is_not_a_standing_grant() {
    let _g = env_lock();
    let home = tmp("once-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("once-proj").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let ws = db.workspace_for(&proj).unwrap();
    // a program-derived approval is one-time
    let t = tasks::create_approval_task(&ctx, &proj, "test", &["STRIPE_SECRET_KEY@default".to_string()], tasks::ApprovalKind::Once).unwrap();
    assert_eq!(t.expects, tasks::APPROVAL_ONCE);
    tasks::answer_approval(&ctx, &t, tasks::Decision::Allow, None).unwrap();
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Answered, "the answer is recorded");
    assert!(db.grant_source(&ws.id, "STRIPE_SECRET_KEY", "default").unwrap().is_none(), "but no grant was written");
    assert!(matches!(trust::gate(&db, &ws, "STRIPE_SECRET_KEY", "default", true, true).unwrap(), trust::Gate::NeedsApproval { .. }), "the next bare request asks again");
    // an ordinary (human-facing) sensitive approval does persist
    let t2 = tasks::create_approval_task(&ctx, &proj, "test", &["STRIPE_SECRET_KEY@default".to_string()], tasks::ApprovalKind::Sensitive).unwrap();
    tasks::answer_approval(&ctx, &t2, tasks::Decision::Allow, None).unwrap();
    assert_eq!(db.grant_source(&ws.id, "STRIPE_SECRET_KEY", "default").unwrap().as_deref(), Some(db::GRANT_SENSITIVE));
    std::env::remove_var("TOKENSTASH_HOME");
    std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn a_denied_approval_is_remembered() {
    let _g = env_lock();
    let home = tmp("deny-approval-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("deny-approval-proj").canonicalize().unwrap();
    // outside every trust root, so a stash hit needs approval
    let cfg = Config { trust_roots: vec![], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-test-aaaaaaaaaaaaaaaa".to_string())).unwrap();
    let names = vec!["OPENAI_API_KEY".to_string()];
    let out = need::need(&ctx, &proj, "test", &names, &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("expected pending, got {o:?}") };
    let t = db.get_task(&tid).unwrap().unwrap();
    assert_eq!(t.kind, db::TaskKind::Approval);
    tasks::answer_approval(&ctx, &t, tasks::Decision::Deny, None).unwrap();
    // asking again within the TTL is refused without a new card
    let out2 = need::need(&ctx, &proj, "test", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(&out2[0], need::Outcome::Denied { .. }), "got {:?}", out2[0]);
    assert_eq!(db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().len(), 0, "no fresh approval card was filed");
    // an older denial for a DIFFERENT key is still honoured after a newer one
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_test_bbbbbbbbbbbbbbbb".to_string())).unwrap();
    let out_g = need::need(&ctx, &proj, "test", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let gid = match &out_g[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&gid).unwrap().unwrap(), tasks::Decision::Deny, None).unwrap();
    let both = need::need(&ctx, &proj, "test", &["OPENAI_API_KEY".to_string(), "GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(both.iter().all(|o| matches!(o, need::Outcome::Denied { .. })), "both denials must be remembered: {both:?}");
    assert_eq!(db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().len(), 0);
    // --force asks again
    let out3 = need::need(&ctx, &proj, "test", &names, &need::NeedOpts { force: true, ..Default::default() }).unwrap();
    assert!(matches!(&out3[0], need::Outcome::Pending { .. }));
    std::env::remove_var("TOKENSTASH_HOME");
    std::env::remove_var("TOKENSTASH_STASH");
}


fn rot_ctx_home(name: &str) -> (PathBuf, PathBuf) {
    let home = tmp(&format!("{name}-home"));
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp(&format!("{name}-proj")).canonicalize().unwrap();
    (home, proj)
}

#[test]
fn a_stale_key_is_a_miss_with_the_reason_on_the_card() {
    let _g = env_lock();
    let (home, proj) = rot_ctx_home("stale-miss");
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let names = vec!["OPENAI_API_KEY".to_string()];
    // store via a paste
    let t = tasks::create_secret_task(&ctx, &proj, "test", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-old-aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    assert!(matches!(need::need(&ctx, &proj, "test", &names, &Default::default()).unwrap()[0], need::Outcome::Injected { .. }));
    // mark stale → the next need is a miss whose card carries the reason
    db.mark_stale("OPENAI_API_KEY", "default", true, Some("rejected by OpenAI (HTTP 401) on 2026-08-26, reported by claude-code in demo"), Some(db::STALE_REPORT)).unwrap();
    let out = need::need(&ctx, &proj, "test", &names, &Default::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let card = db.get_task(&tid).unwrap().unwrap();
    assert!(card.why.as_deref().unwrap().contains("reported by claude-code in demo"), "{:?}", card.why);
    // the old value is still in the stash (self-heal path), not injected
    assert!(stash.get(&stash::stash_key("OPENAI_API_KEY", "default")).unwrap().is_some());
    // answering with a new value clears stale and injects
    tasks::answer_secret(&ctx, &card, SecretString::from("sk-new-bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(!m.stale && m.stale_reason.is_none());
    assert!(std::fs::read_to_string(proj.join(".env.local")).unwrap().contains("sk-new-"));
    std::env::remove_var("TOKENSTASH_HOME"); std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn rotate_files_the_card_and_rewrites_every_project_holding_the_old_value() {
    let _g = env_lock();
    let (home, proj_a) = rot_ctx_home("rotate");
    let proj_b = tmp("rotate-proj-b").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj_a.clone(), proj_b.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let names = vec!["GROQ_API_KEY".to_string()];
    let t = tasks::create_secret_task(&ctx, &proj_a, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_old_aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    pair(&db, &proj_b, "GROQ_API_KEY");
    need::need(&ctx, &proj_b, "test", &names, &Default::default()).unwrap(); // delivered to B too
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"));
    let card = tasks::rotate(&ctx, &proj_a, "test", "GROQ_API_KEY", "default").unwrap();
    assert!(db.get_secret("GROQ_API_KEY", "default").unwrap().unwrap().stale);
    assert!(card.why.as_deref().unwrap().contains("rotate"));
    tasks::answer_secret(&ctx, &card, SecretString::from("gsk_new_bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    assert!(std::fs::read_to_string(proj_a.join(".env.local")).unwrap().contains("gsk_new_"));
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_new_"), "project B still held the old value and must be rewritten");
    assert!(!std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"));
    std::env::remove_var("TOKENSTASH_HOME"); std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn report_bad_needs_standing_and_is_rate_limited() {
    let _g = env_lock();
    let (home, proj) = rot_ctx_home("report");
    let stranger = tmp("report-stranger").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // an unregistered name: no liveness check, so the report itself decides
    let t = tasks::create_secret_task(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("custom-aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    // a project that never received the key has no standing
    assert_eq!(tasks::report_bad(&ctx, &stranger, "evil", "MY_CUSTOM_TOKEN", "default", Some(401)).unwrap(), tasks::ReportOutcome::Ignored);
    assert!(!db.get_secret("MY_CUSTOM_TOKEN", "default").unwrap().unwrap().stale);
    // an unknown name is indistinguishable from an ignored one
    assert_eq!(tasks::report_bad(&ctx, &proj, "test", "NOT_A_KEY", "default", Some(401)).unwrap(), tasks::ReportOutcome::Ignored);
    // the delivering project can report; the message is scrubbed of the value
    let r = tasks::report_bad(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", Some(401)).unwrap();
    assert_eq!(r, tasks::ReportOutcome::MarkedStale);
    let m = db.get_secret("MY_CUSTOM_TOKEN", "default").unwrap().unwrap();
    assert!(m.stale);
    assert!(m.stale_reason.as_deref().unwrap().contains("by test in"), "{:?}", m.stale_reason);
    let audit = db.recent_audit(5).unwrap();
    assert!(audit.iter().any(|a| a.3 == "report"));
    assert!(audit.iter().all(|a| !a.6.as_deref().unwrap_or("").contains("custom-")), "only the status is persisted, never provider text");
    // a second report inside the TTL is ignored (cooldown)
    db.mark_stale("MY_CUSTOM_TOKEN", "default", false, None, Some(db::STALE_REPORT)).unwrap();
    assert_eq!(tasks::report_bad(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", Some(401)).unwrap(), tasks::ReportOutcome::Ignored);
    assert!(!db.get_secret("MY_CUSTOM_TOKEN", "default").unwrap().unwrap().stale);
    // ...but a report about a NEWLY stored value is not shadowed by the old cooldown
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let t2 = tasks::create_secret_task(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t2, SecretString::from("custom-bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(tasks::report_bad(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", Some(401)).unwrap(), tasks::ReportOutcome::MarkedStale, "cooldown must reset when the value changes");
    std::env::remove_var("TOKENSTASH_HOME"); std::env::remove_var("TOKENSTASH_STASH");
}


#[test]
fn a_probe_ok_never_cancels_a_human_rotation() {
    let dir = tmp("rotate-vs-verify");
    let db = Db::open(&dir.join("t.db")).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "K".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    db.mark_stale("K", "default", true, Some(Db::ROTATE_REASON), Some(db::STALE_ROTATE)).unwrap();
    db.set_verified("K", "default").unwrap();
    let m = db.get_secret("K", "default").unwrap().unwrap();
    assert!(m.stale, "a human rotation survives a probe saying the old key is still live");
    assert!(m.last_verified.is_some());
    // a report-driven stale IS cleared by a probe Ok
    db.mark_stale("K", "default", true, Some("rejected by X (HTTP 401) ..."), Some(db::STALE_REPORT)).unwrap();
    db.set_verified("K", "default").unwrap();
    assert!(!db.get_secret("K", "default").unwrap().unwrap().stale);
}

#[test]
fn a_stale_key_still_goes_through_the_trust_gate_and_generated_names_regenerate() {
    let _g = env_lock();
    let (home, proj) = rot_ctx_home("stale-gate");
    let outside = tmp("stale-gate-outside").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &proj, "test", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-old-aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    db.mark_stale("OPENAI_API_KEY", "default", true, Some("rejected ..."), Some(db::STALE_REPORT)).unwrap();
    // outside the trust roots: an APPROVAL card, not a paste card into the stranger's file
    let out = need::need(&ctx, &outside, "test", &["OPENAI_API_KEY".to_string()], &Default::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    assert_eq!(db.get_task(&tid).unwrap().unwrap().kind, db::TaskKind::Approval);
    assert!(!outside.join(".env.local").exists());
    // generated secrets never become paste cards: a stale AUTH_SECRET regenerates
    need::need(&ctx, &proj, "test", &["AUTH_SECRET".to_string()], &Default::default()).unwrap();
    db.mark_stale("AUTH_SECRET", "default", true, Some("reported ..."), Some(db::STALE_REPORT)).unwrap();
    let out = need::need(&ctx, &proj, "test", &["AUTH_SECRET".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { generated: true, .. }), "{:?}", out[0]);
    assert!(!db.get_secret("AUTH_SECRET", "default").unwrap().unwrap().stale);
    std::env::remove_var("TOKENSTASH_HOME"); std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn rotation_reports_projects_it_could_not_rewrite() {
    let _g = env_lock();
    let (home, proj_a) = rot_ctx_home("rotate-skip");
    let proj_b = tmp("rotate-skip-b").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj_a.clone(), proj_b.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &proj_a, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_old_aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    pair(&db, &proj_b, "GROQ_API_KEY");
    need::need(&ctx, &proj_b, "test", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    // B commits its env file (the classic mistake) → the rewrite must refuse and say so
    let git = |args: &[&str]| { std::process::Command::new("git").arg("-C").arg(&proj_b).args(args).env("GIT_AUTHOR_NAME","t").env("GIT_AUTHOR_EMAIL","t@t").env("GIT_COMMITTER_NAME","t").env("GIT_COMMITTER_EMAIL","t@t").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap(); };
    git(&["init", "-q", "."]); git(&["add", "-f", ".env.local"]); git(&["commit", "-q", "-m", "oops"]);
    let card = tasks::rotate(&ctx, &proj_a, "human", "GROQ_API_KEY", "default").unwrap();
    let r = tasks::answer_secret(&ctx, &card, SecretString::from("gsk_new_bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation: Some(rep), .. } = r else { panic!("expected a rotation report") };
    assert_eq!(rep.skipped.len(), 1, "{rep:?}");
    assert!(rep.skipped[0].0 == proj_b.to_string_lossy() && rep.skipped[0].1.contains("tracked by git"));
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"), "B keeps the old value and the human is told");
    std::env::remove_var("TOKENSTASH_HOME"); std::env::remove_var("TOKENSTASH_STASH");
}


#[test]
fn rotation_never_rewrites_a_project_without_a_standing_grant_and_ordinary_pastes_are_not_rotations() {
    let _g = env_lock();
    let (home, proj_a) = rot_ctx_home("rotate-gate");
    let proj_b = tmp("rotate-gate-b").canonicalize().unwrap();
    // B is outside the trust roots: it received the key once via a one-time (run) approval
    let cfg = Config { trust_roots: vec![proj_a.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &proj_a, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_old_aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    let ws_b = db.workspace_for(&proj_b).unwrap();
    let once = tasks::create_approval_task(&ctx, &proj_b, "run", &["GROQ_API_KEY@default".to_string()], tasks::ApprovalKind::Once).unwrap();
    tasks::answer_approval(&ctx, &once, tasks::Decision::Allow, None).unwrap();
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"));
    assert!(db.grant_source(&ws_b.id, "GROQ_API_KEY", "default").unwrap().is_none(), "one-time approval left no grant");
    // rotate from A: B must NOT be rewritten, and the human is told
    let card = tasks::rotate(&ctx, &proj_a, "human", "GROQ_API_KEY", "default").unwrap();
    let r = tasks::answer_secret(&ctx, &card, SecretString::from("gsk_new_bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation: Some(rep), .. } = r else { panic!() };
    assert!(rep.skipped.iter().any(|(p, why)| p == &proj_b.to_string_lossy() && why.contains("no standing grant")), "{rep:?}");
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"));
    // an ordinary paste in another project with a different value is NOT a rotation
    let proj_c = tmp("rotate-gate-c").canonicalize().unwrap();
    let cfg2 = Config { trust_roots: vec![proj_a.clone(), proj_c.clone()], ..Default::default() };
    let ctx2 = tasks::Ctx { cfg: &cfg2, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let tc = tasks::create_secret_task(&ctx2, &proj_c, "test", "OTHER_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx2, &tc, SecretString::from("other-aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    need::need(&ctx2, &proj_a, "test", &["OTHER_KEY".to_string()], &Default::default()).unwrap();
    let ta = tasks::create_secret_task(&ctx2, &proj_a, "test", "OTHER_KEY", "default", &Default::default()).unwrap();
    let r = tasks::answer_secret(&ctx2, &ta, SecretString::from("other-bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation, .. } = r else { panic!() };
    assert!(rotation.is_none(), "a fresh paste is not a rotation");
    assert!(std::fs::read_to_string(proj_c.join(".env.local")).unwrap().contains("other-aaaa"), "C keeps its own value");
    std::env::remove_var("TOKENSTASH_HOME"); std::env::remove_var("TOKENSTASH_STASH");
}


#[test]
fn an_ordinary_card_answered_after_a_stale_mark_elsewhere_does_not_propagate() {
    let _g = env_lock();
    let (home, proj_a) = rot_ctx_home("ordinary-vs-stale");
    let proj_b = tmp("ordinary-vs-stale-b").canonicalize().unwrap();
    let cfg = Config { trust_roots: vec![proj_a.clone(), proj_b.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // A stores and B receives the key
    let t = tasks::create_secret_task(&ctx, &proj_a, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_old_aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    pair(&db, &proj_b, "GROQ_API_KEY");
    need::need(&ctx, &proj_b, "test", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    // an ORDINARY card is filed in a third project (say the key was forgotten there and re-requested by hand)
    let proj_c = tmp("ordinary-vs-stale-c").canonicalize().unwrap();
    let ordinary = tasks::create_secret_task(&ctx, &proj_c, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    assert_ne!(ordinary.expects, tasks::EXPECTS_REPLACE);
    // meanwhile the key is marked stale by a report elsewhere
    db.mark_stale("GROQ_API_KEY", "default", true, Some("reported ..."), Some(db::STALE_REPORT)).unwrap();
    // answering the ordinary card must not rewrite A and B
    let r = tasks::answer_secret(&ctx, &ordinary, SecretString::from("gsk_new_cccccccccccccccc".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation, .. } = r else { panic!() };
    assert!(rotation.is_none());
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"), "B untouched by an ordinary answer");
    // a REPLACEMENT card (the stale-miss branch) does propagate
    db.mark_stale("GROQ_API_KEY", "default", true, Some("reported ..."), Some(db::STALE_REPORT)).unwrap();
    let out = need::need(&ctx, &proj_a, "test", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let card = db.get_task(&tid).unwrap().unwrap();
    assert_eq!(card.expects, tasks::EXPECTS_REPLACE);
    tasks::answer_secret(&ctx, &card, SecretString::from("gsk_new_dddddddddddddddd".to_string()), true).unwrap();
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_new_dddd"), "B held the ORIGINAL stale value (the ordinary answer changed the stash in between); the replacement still reaches it");
    std::env::remove_var("TOKENSTASH_HOME"); std::env::remove_var("TOKENSTASH_STASH");
}


// ---------------------------------------------------------------------------------------
// verify-on-use (§14.7)

fn verify_setup(tag: &str) -> (PathBuf, PathBuf) {
    let home = tmp(&format!("verify-{tag}-home"));
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp(&format!("verify-{tag}-proj")).canonicalize().unwrap();
    (home, proj)
}

fn seed(db: &Db, stash: &dyn stash::Stash, proj: &std::path::Path, name: &str, value: &str, last_verified: Option<String>) {
    stash.set(&stash::stash_key(name, "default"), &SecretString::from(value.to_string())).unwrap();
    pair(db, proj, name);
    db.upsert_secret(&db::SecretMeta { name: name.into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
}

#[test]
fn at_use_rejection_becomes_a_replace_card_and_writes_nothing() {
    let _env = env_lock();
    let (home, proj) = verify_setup("reject");
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |c: &registry::Check| { calls.set(calls.get() + 1); assert!(c.url.contains("api.openai.com")); validate::Liveness::Rejected(401) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-dead-aaaaaaaaaaaaaaaaaaaa", None);
    let out = need::need(&ctx, &proj, "claude-code", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let (tid, title) = match &out[0] { need::Outcome::Pending { task_id, title, .. } => (task_id.clone(), title.clone()), o => panic!("expected a replace card, got {o:?}") };
    assert_eq!(calls.get(), 1);
    assert!(!envfile::has(&proj, ".env.local", "OPENAI_API_KEY"), "a rejected key must not be written");
    let t = db.get_task(&tid).unwrap().unwrap();
    assert_eq!(t.expects, tasks::EXPECTS_REPLACE, "{title}");
    assert!(t.why.as_deref().unwrap_or("").contains("rejected by OpenAI (HTTP 401)"), "{:?}", t.why);
    assert!(t.why.as_deref().unwrap_or("").contains("found at use by claude-code"));
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.stale);
    assert_eq!(m.stale_source.as_deref(), Some(db::STALE_PROBE));
    assert!(db.recent_audit(10).unwrap().iter().any(|r| r.3 == "probe.rejected"));
    // the value stays: a paste of the same value that the provider now accepts self-heals
    assert!(stash.get(&stash::stash_key("OPENAI_API_KEY", "default")).unwrap().is_some());
    // a stale key is never probed again on the next call; the card is simply reused
    let out2 = need::need(&ctx, &proj, "claude-code", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(&out2[0], need::Outcome::Pending { task_id, .. } if *task_id == tid));
    assert_eq!(calls.get(), 1);
}

#[test]
fn at_use_ok_refreshes_and_respects_the_window() {
    let _env = env_lock();
    let (home, proj) = verify_setup("ok");
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Ok };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-live-aaaaaaaaaaaaaaaaaaaa", None);
    let names = ["OPENAI_API_KEY".to_string()];
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: false, .. }), "{out:?}");
    assert_eq!(calls.get(), 1);
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.last_verified.is_some());
    assert!(m.next_probe.as_deref().unwrap() > now().as_str(), "an Ok leaves the one-minute floor, nothing longer");
    let in_2m = (chrono::Utc::now() + chrono::Duration::minutes(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(m.next_probe.as_deref().unwrap() < in_2m.as_str(), "the window itself comes from last_verified");
    // inside the window: no second probe
    need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert_eq!(calls.get(), 1);
    // an old timestamp is due again; so is a future one (clock moved back) or garbage
    for stamp in ["2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z", "not a date"] {
        db.conn.execute("UPDATE secrets SET last_verified=?1, next_probe=NULL", [stamp]).unwrap();
        let before = calls.get();
        need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
        assert_eq!(calls.get(), before + 1, "{stamp} must count as unverified");
    }
    // `always` probes every call; `never` never does
    let cfg_always = Config { verify_every: config::VerifyEvery::Always, ..cfg.clone() };
    let ctx_a = tasks::Ctx { cfg: &cfg_always, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    let before = calls.get();
    db.conn.execute("UPDATE secrets SET next_probe=NULL", []).unwrap();
    need::need(&ctx_a, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    // ...but never more than once a minute: a `need` loop is not a request loop
    let out = need::need(&ctx_a, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "inside the floor the caller is told it was not re-checked");
    assert_eq!(calls.get(), before + 1);
    db.conn.execute("UPDATE secrets SET next_probe=NULL", []).unwrap();
    need::need(&ctx_a, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert_eq!(calls.get(), before + 2);
    let cfg_never = Config { verify_every: config::VerifyEvery::Never, ..cfg.clone() };
    let ctx_n = tasks::Ctx { cfg: &cfg_never, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    db.conn.execute("UPDATE secrets SET last_verified=NULL, next_probe=NULL", []).unwrap();
    need::need(&ctx_n, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert_eq!(calls.get(), before + 2);
}

#[test]
fn at_use_unknown_delivers_unverified_with_backoff() {
    let _env = env_lock();
    let (home, proj) = verify_setup("unknown");
    let cfg = Config { trust_roots: vec![proj.clone()], verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let verdict = std::cell::RefCell::new(validate::Liveness::Unknown("HTTP 503".into()));
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); verdict.borrow().clone() };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-live-aaaaaaaaaaaaaaaaaaaa", None);
    let names = ["OPENAI_API_KEY".to_string()];
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "{out:?}");
    assert!(envfile::has(&proj, ".env.local", "OPENAI_API_KEY"), "an outage must not block delivery");
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.last_verified.is_none());
    let np = m.next_probe.clone().unwrap();
    assert!(np > now(), "backoff recorded");
    // inside the backoff even `always` does not probe, and the caller is told
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }));
    assert_eq!(calls.get(), 1);
    // rate-limited: a much longer backoff than an outage
    db.conn.execute("UPDATE secrets SET next_probe=NULL", []).unwrap();
    *verdict.borrow_mut() = validate::Liveness::Unknown("HTTP 429".into());
    need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    let in_50m = (chrono::Utc::now() + chrono::Duration::minutes(50)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(m.next_probe.unwrap() > in_50m, "429 backs off for an hour, not ten minutes");
    // 403 is a verdict that will not change: a restricted key waits a whole window
    let cfg_day = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let ctx_d = tasks::Ctx { cfg: &cfg_day, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    db.conn.execute("UPDATE secrets SET next_probe=NULL", []).unwrap();
    *verdict.borrow_mut() = validate::Liveness::Unknown("HTTP 403".into());
    need::need(&ctx_d, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    let in_23h = (chrono::Utc::now() + chrono::Duration::hours(23)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(m.next_probe.unwrap() > in_23h, "403 waits a full window");
    assert!(!m.stale, "403 never stales a key");
}

#[test]
fn at_use_probe_is_skipped_when_not_allowed() {
    let _env = env_lock();
    let (home, proj) = verify_setup("skip");
    let cfg = Config { trust_roots: vec![proj.clone()], verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Rejected(401) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    // registry says not at use (generic 400 reject / metered)
    assert!(registry::lookup("GEMINI_API_KEY").unwrap().check.as_ref().map(|c| !c.at_use).unwrap());
    assert!(registry::lookup("BRAVE_API_KEY").unwrap().check.as_ref().map(|c| !c.at_use).unwrap());
    seed(&db, stash.as_ref(), &proj, "GEMINI_API_KEY", "AIzaSyDEADDEADDEADDEADDEADDEAD", None);
    let out = need::need(&ctx, &proj, "t", &["GEMINI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: false, .. }));
    // no registry check at all
    seed(&db, stash.as_ref(), &proj, "MY_CUSTOM_TOKEN", "custom-token-value-1234567890", None);
    need::need(&ctx, &proj, "t", &["MY_CUSTOM_TOKEN".to_string()], &need::NeedOpts::default()).unwrap();
    // the human stored it with --skip-check: verify_off
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-skip-aaaaaaaaaaaaaaaaaaaa", None);
    db.set_verify_off("OPENAI_API_KEY", "default", true).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{out:?}");
    // a project that needs approval gets no probe: the probe transmits the key
    // a directory without a grant gets no probe: the probe transmits the key
    let cfg_untrusted = Config { trust_roots: vec![], verify_every: config::VerifyEvery::Always, ..Default::default() };
    let ctx_u = tasks::Ctx { cfg: &cfg_untrusted, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    db.revoke_workspace(&db.find_workspace(&proj).unwrap().unwrap().id).unwrap();
    std::fs::remove_file(proj.join(".env.local")).unwrap(); // else on-disk equivalence would open it
    db.set_verify_off("OPENAI_API_KEY", "default", false).unwrap();
    let out = need::need(&ctx_u, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
    // a human-requested rotation is not re-probed either
    db.mark_stale("OPENAI_API_KEY", "default", true, Some(Db::ROTATE_REASON), Some(db::STALE_ROTATE)).unwrap();
    need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert_eq!(calls.get(), 0, "no probe may have run in this test");
}

#[test]
fn skip_check_store_turns_verify_off_until_a_probe_says_ok() {
    let _env = env_lock();
    let (home, proj) = verify_setup("skipcheck");
    let cfg = Config { trust_roots: vec![proj.clone()], verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Rejected(401) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    // with the check: the paste itself is refused
    let t = db.get_task(&tid).unwrap().unwrap();
    assert!(tasks::answer_secret(&ctx, &t, SecretString::from("sk-restricted-aaaaaaaaaaaaaa".to_string()), false).is_err());
    assert_eq!(calls.get(), 1);
    // --skip-check: stored, and verify-on-use is off for this key
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-restricted-aaaaaaaaaaaaaa".to_string()), true).unwrap();
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.verify_off);
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "a key the human stored past the check must not be re-rejected: {out:?}");
    assert_eq!(calls.get(), 1);
    // a probe that says Ok (e.g. `check`) turns it back on
    db.set_verified("OPENAI_API_KEY", "default").unwrap();
    assert!(!db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().verify_off);
}

#[test]
fn approval_delivery_is_verified_too() {
    let _env = env_lock();
    let (home, proj) = verify_setup("approval");
    let cfg = Config { trust_roots: vec![], verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let stub = |_: &registry::Check| validate::Liveness::Rejected(401);
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    // stored, but never paired into this directory: the pairing card comes first
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-dead-aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "OPENAI_API_KEY".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    assert!(tid.starts_with("a_"), "unpaired directory: pairing card first");
    match tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap() {
        tasks::AnswerResult::Approved { injected, replaced } => { assert!(injected.is_empty()); assert_eq!(replaced, vec!["OPENAI_API_KEY".to_string()]); }
        o => panic!("{o:?}"),
    }
    assert!(!envfile::has(&proj, ".env.local", "OPENAI_API_KEY"), "approval must not bypass the probe");
    assert!(db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale);
    let pid = proj.to_string_lossy().to_string();
    let rt = db.open_secret_task(&pid, "OPENAI_API_KEY", "default").unwrap().expect("replacement card filed for this project");
    assert_eq!(rt.expects, tasks::EXPECTS_REPLACE);
    // the agent's `wait` now sees the approval Answered — and must not inject the dead key
    let mut outcomes = vec![need::Outcome::Pending { name: "OPENAI_API_KEY".into(), identity: "default".into(), task_id: tid.clone(), title: String::new(), url: None }];
    need::wait(&ctx, &proj, &mut outcomes, std::time::Duration::from_millis(10)).unwrap();
    match &outcomes[0] {
        need::Outcome::Pending { task_id, .. } => assert_eq!(*task_id, rt.id, "wait re-pends on the Replace card"),
        o => panic!("wait must not inject a stale key: {o:?}"),
    }
    assert!(!envfile::has(&proj, ".env.local", "OPENAI_API_KEY"));
}

#[test]
fn a_verdict_for_a_value_no_longer_stored_is_discarded() {
    let _env = env_lock();
    let (home, proj) = verify_setup("race");
    let cfg = Config { trust_roots: vec![proj.clone()], verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    // while the probe is "in flight", another process replaces the key
    let stub = |_: &registry::Check| {
        stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-new-aaaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
        validate::Liveness::Rejected(401)
    };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-old-aaaaaaaaaaaaaaaaaaaaa", None);
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "{out:?}");
    assert!(!db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale, "the old value's verdict must not stale the new value");
    let written = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(written.contains("sk-new-"), "the value stored now is what lands, not the one probed: {written}");
    assert!(!written.contains("sk-old-"));
}

#[test]
fn verify_every_parses_strictly() {
    use config::VerifyEvery::*;
    assert_eq!(config::VerifyEvery::parse("24h").unwrap(), Every(std::time::Duration::from_secs(86400)));
    assert_eq!(config::VerifyEvery::parse("30m").unwrap(), Every(std::time::Duration::from_secs(1800)));
    assert_eq!(config::VerifyEvery::parse("always").unwrap(), Always);
    assert_eq!(config::VerifyEvery::parse(" never ").unwrap(), Never);
    assert_eq!(config::VerifyEvery::parse("8760h").unwrap(), Every(std::time::Duration::from_secs(8760 * 3600)), "a year is the cap");
    let c: Config = toml::from_str("verify_every = \"90m\"").unwrap();
    assert!(toml::to_string(&c).unwrap().contains("verify_every = \"90m\""));
    assert!(toml::from_str::<Config>("verify_evry = \"never\"").is_err(), "a typo must not silently keep the default");
    for bad in ["0m", "0h", "5s", "", "daily", "h", "-1h", "+5h", "5м", "24ｈ", "99999999999999999999h", "9000h", "1.5h", " 1 h"] {
        assert!(config::VerifyEvery::parse(bad).is_err(), "{bad:?} must be rejected");
    }
    let c: Config = toml::from_str("verify_every = \"2h\"").unwrap();
    assert_eq!(c.verify_every, Every(std::time::Duration::from_secs(7200)));
    assert!(toml::from_str::<Config>("verify_every = \"sometimes\"").is_err());
    assert_eq!(Config::default().verify_every, Every(std::time::Duration::from_secs(86400)));
    let s = toml::to_string(&Config::default()).unwrap();
    assert!(s.contains("verify_every = \"24h\""), "{s}");
}

#[test]
fn registry_at_use_is_a_deliberate_allowlist() {
    for p in registry::all() {
        let Some(c) = &p.check else { continue };
        if c.at_use {
            assert!(!c.reject_status.contains(&400), "{}: a generic 400 reject cannot run unattended", p.name);
            assert!(c.reject_status.iter().all(|s| *s == 403), "{}: only a documented 403-for-bad-token provider may add a reject status at use", p.name);
            assert!(!c.url.contains("search"), "{}: a metered endpoint cannot run unattended", p.name);
            assert!(c.url.starts_with("https://"), "{}", p.name);
        }
    }
    assert!(registry::lookup("OPENAI_API_KEY").unwrap().check.as_ref().unwrap().at_use);
    assert!(!registry::lookup("CLOUDFLARE_API_TOKEN").unwrap().check.as_ref().unwrap().at_use, "200 with status=expired in the body");
    assert!(!registry::lookup("ELEVENLABS_API_KEY").unwrap().check.as_ref().unwrap().at_use, "401 missing_permissions for a live restricted key");
    assert_eq!(registry::lookup("VERCEL_TOKEN").unwrap().check.as_ref().unwrap().reject_status, vec![403], "Vercel answers 403 for a bad token");
}

/// A one-shot loopback HTTP server: records the request head, answers with `response`.
fn loopback(response: &'static str) -> (String, std::sync::mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/probe", l.local_addr().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    let h = std::thread::spawn(move || {
        l.set_nonblocking(false).unwrap();
        for _ in 0..2 {
            let Ok((mut s, _)) = l.accept() else { return };
            s.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            if response.is_empty() { std::thread::sleep(std::time::Duration::from_secs(3)); return }
            let _ = s.write_all(response.as_bytes());
        }
    });
    (url, rx, h)
}

fn check_for(url: &str, auth: &str) -> registry::Check {
    registry::Check { method: "GET".into(), url: url.into(), auth: auth.into(), headers: Default::default(), reject_status: vec![], at_use: true }
}

#[test]
fn liveness_verdicts_over_loopback() {
    let v = SecretString::from("sk-probe-value-000000000000".to_string());
    let t = std::time::Duration::from_secs(1);
    // 401 → Rejected, and the header is exactly the documented one
    let (url, rx, _h) = loopback("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert_eq!(validate::liveness(&check_for(&url, "bearer"), &v, t), validate::Liveness::Rejected(401));
    let req = rx.recv().unwrap();
    assert!(req.contains("Authorization: Bearer sk-probe-value-000000000000"), "{req}");
    // 403 → Unknown: a restricted key is a live key
    let (url, _rx, _h) = loopback("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(matches!(validate::liveness(&check_for(&url, "bearer"), &v, t), validate::Liveness::Unknown(_)));
    // 200 → Ok
    let (url, _rx, _h) = loopback("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    assert_eq!(validate::liveness(&check_for(&url, "header:xi-api-key"), &v, t), validate::Liveness::Ok);
    // 302 → Unknown, and the redirect is NOT followed: the custom header never leaves for
    // the target. The same listener plays both origins; exactly one request must arrive.
    let (url, rx, _h) = loopback("HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(matches!(validate::liveness(&check_for(&url, "header:xi-api-key"), &v, t), validate::Liveness::Unknown(_)));
    let first = rx.recv().unwrap();
    assert!(first.contains("xi-api-key: sk-probe-value"), "{first}");
    assert!(rx.recv_timeout(std::time::Duration::from_millis(500)).is_err(), "the redirect target must never receive a request");
    // no response inside the timeout → Unknown, and the error text does not carry the key
    let (url, _rx, _h) = loopback("");
    let started = std::time::Instant::now();
    match validate::liveness(&check_for(&url, "query:key"), &v, t) {
        validate::Liveness::Unknown(e) => assert!(!e.contains("sk-probe"), "{e}"),
        o => panic!("{o:?}"),
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
}


#[test]
fn probe_budget_delivers_unverified_without_taking_a_lease() {
    let _env = env_lock();
    let (home, proj) = verify_setup("budget");
    let cfg = Config { trust_roots: vec![proj.clone()], verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Ok };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-live-aaaaaaaaaaaaaaaaaaaa", None);
    let names = ["OPENAI_API_KEY".to_string()];
    let out = need::need_with_budget(&ctx, &proj, "t", &names, &need::NeedOpts::default(), &mut need::ProbeBudget::exhausted()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "{out:?}");
    assert_eq!(calls.get(), 0);
    assert!(db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().next_probe.is_none(), "no lease taken: the next call may probe");
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: false, .. }));
    assert_eq!(calls.get(), 1);
}

#[test]
fn old_databases_get_stale_source_backfilled() {
    let home = tmp("migrate");
    let path = home.join("old.db");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE secrets (name TEXT NOT NULL, identity TEXT NOT NULL DEFAULT 'default', provider TEXT, sensitive INTEGER NOT NULL DEFAULT 0, source_url TEXT, created TEXT NOT NULL, last_used TEXT, stale INTEGER NOT NULL DEFAULT 0, last_verified TEXT, stale_reason TEXT, PRIMARY KEY(name, identity));").unwrap();
        c.execute("INSERT INTO secrets (name, created, stale, stale_reason) VALUES ('ROT', '2026-01-01T00:00:00Z', 1, ?1)", [format!("{} (old)", Db::ROTATE_REASON)]).unwrap();
        c.execute("INSERT INTO secrets (name, created, stale, stale_reason) VALUES ('REP', '2026-01-01T00:00:00Z', 1, 'rejected by X (HTTP 401) ...')", []).unwrap();
        c.execute("INSERT INTO secrets (name, created, stale) VALUES ('OK', '2026-01-01T00:00:00Z', 0)", []).unwrap();
    }
    let db = Db::open(&path).unwrap();
    assert_eq!(db.get_secret("ROT", "default").unwrap().unwrap().stale_source.as_deref(), Some(db::STALE_ROTATE));
    assert_eq!(db.get_secret("REP", "default").unwrap().unwrap().stale_source.as_deref(), Some(db::STALE_REPORT));
    let ok = db.get_secret("OK", "default").unwrap().unwrap();
    assert!(ok.stale_source.is_none() && ok.next_probe.is_none() && !ok.verify_off);
    // and the rotation survives a probe saying Ok, the report does not
    db.set_verified("ROT", "default").unwrap();
    db.set_verified("REP", "default").unwrap();
    assert!(db.get_secret("ROT", "default").unwrap().unwrap().stale);
    assert!(!db.get_secret("REP", "default").unwrap().unwrap().stale);
    // reopening is idempotent
    drop(db);
    Db::open(&path).unwrap();
}

#[test]
fn agent_names_are_short_and_printable() {
    assert_eq!(need::clean_agent("claude-code"), "claude-code");
    assert_eq!(need::clean_agent("Codex CLI/1.2"), "Codex CLI1.2");
    assert_eq!(need::clean_agent("<b>PASTE YOUR KEY AT http://evil</b>"), "bPASTE YOUR KEY AT httpevilb");
    assert_eq!(need::clean_agent(&"x".repeat(200)).len(), 48);
    assert_eq!(need::clean_agent("\n\t\u{202e}"), "agent");
}

#[test]
fn unverified_reports_count_toward_the_cooldown() {
    let _env = env_lock();
    let (home, proj) = verify_setup("reportcool");
    let cfg = Config { trust_roots: vec![proj.clone()], verify_every: config::VerifyEvery::Never, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Unknown("HTTP 403".into()) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-restricted-aaaaaaaaaaaaaaa", None);
    need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    // a report that the provider cannot confirm (403 → no verdict) is one probe, then silence
    for _ in 0..3 {
        tasks::report_bad(&ctx, &proj, "t", "OPENAI_API_KEY", "default", Some(403)).unwrap();
    }
    assert_eq!(calls.get(), 1, "an agent looping secrets_report_invalid must not loop the provider");
    assert!(!db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale);
}

#[test]
fn skipping_the_check_on_an_uncheckable_key_does_not_flag_it() {
    let _env = env_lock();
    let (home, proj) = verify_setup("uncheckable");
    let cfg = Config { trust_roots: vec![proj.clone()], ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let out = need::need(&ctx, &proj, "t", &["MY_CUSTOM_TOKEN".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_secret(&ctx, &db.get_task(&tid).unwrap().unwrap(), SecretString::from("custom-token-value-1234567890".to_string()), true).unwrap();
    assert!(!db.get_secret("MY_CUSTOM_TOKEN", "default").unwrap().unwrap().verify_off, "nothing to skip for a key without a probe");
}


// ---------------------------------------------------------------------------------------
// trust v2 (§13.1 / §13.5)

fn v2_world(tag: &str) -> (PathBuf, PathBuf) {
    let home = tmp(&format!("v2-{tag}-home"));
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp(&format!("v2-{tag}-proj")).canonicalize().unwrap();
    (home, proj)
}

#[test]
fn first_contact_files_one_pairing_card_and_allow_broad_covers_registry_keys_only() {
    let _g = env_lock();
    let (home, proj) = v2_world("pairing");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    for (n, v) in [("OPENAI_API_KEY", "sk-aaaaaaaaaaaaaaaaaaaa"), ("GROQ_API_KEY", "gsk_bbbbbbbbbbbbbbbb"), ("STRIPE_SECRET_KEY", "sk_live_cccccccccccc"), ("MY_INTERNAL_TOKEN", "internal-dddddddddddd")] {
        stash.set(&stash::stash_key(n, "default"), &SecretString::from(v.to_string())).unwrap();
        db.upsert_secret(&db::SecretMeta { name: n.into(), identity: "default".into(), provider: None, sensitive: n == "STRIPE_SECRET_KEY", source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    }
    let names: Vec<String> = ["OPENAI_API_KEY", "GROQ_API_KEY", "STRIPE_SECRET_KEY", "MY_INTERNAL_TOKEN"].iter().map(|s| s.to_string()).collect();
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(out.iter().all(|o| matches!(o, need::Outcome::Pending { .. })), "{out:?}");
    assert!(!proj.join(".env.local").exists(), "nothing written before the human answers");
    // two cards: one pairing card for the two ordinary keys, one sensitive card for the rest
    let ids: std::collections::BTreeSet<String> = out.iter().filter_map(|o| if let need::Outcome::Pending { task_id, .. } = o { Some(task_id.clone()) } else { None }).collect();
    assert_eq!(ids.len(), 2, "{out:?}");
    let open = db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap();
    let pairing = open.iter().find(|t| t.expects == tasks::APPROVAL_PAIRING).expect("pairing card");
    let sens = open.iter().find(|t| t.expects == tasks::APPROVAL_SENSITIVE).expect("sensitive card");
    assert_eq!(pairing.names.len(), 2);
    assert!(sens.names.iter().any(|n| n.starts_with("STRIPE")) && sens.names.iter().any(|n| n.starts_with("MY_INTERNAL")), "sensitive AND unregistered: {:?}", sens.names);
    assert!(pairing.why.as_deref().unwrap().contains(".env.local"), "card names the destination file");
    // a second request while the card is open merges into it, no new card
    stash.set(&stash::stash_key("RESEND_API_KEY", "default"), &SecretString::from("re_eeeeeeeeeeeeeeee".to_string())).unwrap();
    need::need(&ctx, &proj, "t", &["RESEND_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert_eq!(db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().len(), 2);
    assert_eq!(db.get_task(&pairing.id).unwrap().unwrap().names.len(), 3);
    // Allow broad: the listed keys + any registry non-sensitive key for `default` here
    tasks::answer_approval(&ctx, &db.get_task(&pairing.id).unwrap().unwrap(), tasks::Decision::AllowBroad, None).unwrap();
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.has_broad_grant(&ws.id, "default").unwrap());
    assert_eq!(db.grant_source(&ws.id, "OPENAI_API_KEY", "default").unwrap().as_deref(), Some(db::GRANT_PAIRING));
    assert!(envfile::has(&proj, ".env.local", "OPENAI_API_KEY") && envfile::has(&proj, ".env.local", "GROQ_API_KEY"));
    assert!(!envfile::has(&proj, ".env.local", "STRIPE_SECRET_KEY"), "sensitive keys wait for their own card");
    // a never-listed registry key is now silent; sensitive/unregistered still are not
    stash.set(&stash::stash_key("MISTRAL_API_KEY", "default"), &SecretString::from("mistral-ffffffffffffffff".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["MISTRAL_API_KEY".to_string(), "STRIPE_SECRET_KEY".to_string(), "MY_INTERNAL_TOKEN".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{out:?}");
    assert!(matches!(out[1], need::Outcome::Pending { .. }) && matches!(out[2], need::Outcome::Pending { .. }));
    // the sensitive card cannot be answered broadly
    assert!(tasks::answer_approval(&ctx, &db.get_task(&sens.id).unwrap().unwrap(), tasks::Decision::AllowBroad, None).is_err());
    tasks::answer_approval(&ctx, &db.get_task(&sens.id).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    assert_eq!(db.grant_source(&ws.id, "STRIPE_SECRET_KEY", "default").unwrap().as_deref(), Some(db::GRANT_SENSITIVE));
    assert!(envfile::has(&proj, ".env.local", "STRIPE_SECRET_KEY"));
    // audit rows say which grant delivered
    let rows = db.recent_audit(50).unwrap();
    assert!(rows.iter().any(|r| r.3 == "inject" && r.4.as_deref() == Some("MISTRAL_API_KEY") && r.7.as_deref() == Some(db::GRANT_BROAD)), "{rows:?}");
    // another directory shares none of it
    let other = tmp("v2-pairing-other").canonicalize().unwrap();
    let out = need::need(&ctx, &other, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
}

#[test]
fn a_denied_pairing_card_is_remembered() {
    let _g = env_lock();
    let (home, proj) = v2_world("deny");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Deny, None).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Denied { .. }), "{out:?}");
    assert_eq!(db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().len(), 0, "no fresh card");
}

#[test]
fn a_paste_grants_exactly_one_key_and_nothing_else() {
    let _g = env_lock();
    let (home, proj) = v2_world("paste");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_secret(&ctx, &db.get_task(&tid).unwrap().unwrap(), SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    let grants = db.grants_for(&ws.id).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!((grants[0].0.as_str(), grants[0].1.as_str(), grants[0].3.as_str()), ("OPENAI_API_KEY", "default", db::GRANT_PASTE));
    // silent from now on here; a second key still pairs
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_bbbbbbbbbbbbbbbb".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
}

#[test]
fn on_disk_equivalence_opens_one_delivery_and_is_not_a_grant() {
    let _g = env_lock();
    let (home, proj) = v2_world("ondisk");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let v = "sk-aaaaaaaaaaaaaaaaaaaa";
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from(v.to_string())).unwrap();
    stash.set(&stash::stash_key("STRIPE_SECRET_KEY", "default"), &SecretString::from("sk_live_cccccccccccc".to_string())).unwrap();
    // a copy that brought its .env.local along
    std::fs::write(proj.join(".env.local"), format!("OPENAI_API_KEY={v}\nSTRIPE_SECRET_KEY=sk_live_cccccccccccc\n")).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string(), "STRIPE_SECRET_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "same value on disk: no card — {out:?}");
    assert!(matches!(out[1], need::Outcome::Pending { .. }), "sensitive keys never use the on-disk check");
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.grants_for(&ws.id).unwrap().is_empty(), "not a grant");
    let rows = db.recent_audit(20).unwrap();
    assert!(rows.iter().any(|r| r.3 == "inject" && r.7.as_deref() == Some(db::GRANT_ON_DISK)));
    // rotation never follows it
    assert!(db.workspaces_granted("OPENAI_API_KEY", "default", true).unwrap().is_empty());
    // a different value on disk: a card, and no second comparison inside the TTL
    let other = tmp("v2-ondisk-other").canonicalize().unwrap();
    std::fs::write(other.join(".env.local"), "OPENAI_API_KEY=sk-guess-000000000000000\n").unwrap();
    let out = need::need(&ctx, &other, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
    std::fs::write(other.join(".env.local"), format!("OPENAI_API_KEY={v}\n")).unwrap();
    let out = need::need(&ctx, &other, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "a guess, then the right value, still waits for the TTL: {out:?}");
    // a symlinked env file is never compared
    let sym = tmp("v2-ondisk-sym").canonicalize().unwrap();
    std::os::unix::fs::symlink(proj.join(".env.local"), sym.join(".env.local")).unwrap();
    assert!(!trust::on_disk_equivalent(&sym, ".env.local", "OPENAI_API_KEY", &SecretString::from(v.to_string())));
}

#[test]
fn v1_approvals_backfill_into_grants_once() {
    let dir = tmp("v2-migrate");
    let path = dir.join("old.db");
    let proj = dir.join("proj"); std::fs::create_dir_all(&proj).unwrap();
    let gone = dir.join("gone");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE approvals (project TEXT NOT NULL, name TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY (project, name));
                         CREATE TABLE bindings (project TEXT NOT NULL, name TEXT NOT NULL, identity TEXT NOT NULL, PRIMARY KEY (project, name));").unwrap();
        let p = proj.canonicalize().unwrap().to_string_lossy().to_string();
        c.execute("INSERT INTO approvals VALUES (?1, '*', 't')", [&p]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'STRIPE_SECRET_KEY', 't')", [&p]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'OPENAI_API_KEY', 't')", [&p]).unwrap();
        c.execute("INSERT INTO bindings VALUES (?1, 'OPENAI_API_KEY', 'work')", [&p]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'GROQ_API_KEY', 't')", [gone.to_string_lossy().to_string()]).unwrap();
    }
    let db = Db::open(&path).unwrap();
    let ws = db.find_workspace(&proj).unwrap().expect("migrated root becomes a workspace");
    assert!(db.has_broad_grant(&ws.id, "default").unwrap(), "`*` → broad");
    assert_eq!(db.grant_source(&ws.id, "STRIPE_SECRET_KEY", "default").unwrap().as_deref(), Some(db::GRANT_BACKFILL));
    assert_eq!(db.grant_source(&ws.id, "OPENAI_API_KEY", "work").unwrap().as_deref(), Some(db::GRANT_BACKFILL), "identity from the binding");
    assert_eq!(db.binding(&ws.id, "OPENAI_API_KEY").unwrap().as_deref(), Some("work"));
    assert!(db.find_workspace(&gone).unwrap().is_none(), "a root that no longer exists gets nothing");
    assert_eq!(db.list_workspaces().unwrap().len(), 1);
    // the old tables are untouched (a 0.1 binary can still open this file), and the
    // migration does not run twice
    let n: i64 = db.conn.query_row("SELECT COUNT(*) FROM approvals", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 4);
    db.revoke_workspace(&ws.id).unwrap();
    drop(db);
    let db = Db::open(&path).unwrap();
    assert!(db.grants_for(&ws.id).unwrap().is_empty(), "user_version guards the backfill");
}

#[test]
fn refused_roots_never_pair() {
    let _g = env_lock();
    let (home, _proj) = v2_world("refused");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let err = need::need(&ctx, std::path::Path::new("/tmp"), "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap_err().to_string();
    assert!(err.contains("shared temporary directory"), "{err}");
    assert!(db.list_workspaces().unwrap().is_empty());
}


#[test]
fn the_on_disk_check_is_rate_limited_per_key_not_per_directory() {
    let _g = env_lock();
    let (home, _proj) = v2_world("oracle");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let v = "sk-aaaaaaaaaaaaaaaaaaaa";
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from(v.to_string())).unwrap();
    // guess #1 in one directory, then the right value in a brand-new directory: no comparison
    let g1 = tmp("v2-oracle-g1").canonicalize().unwrap();
    std::fs::write(g1.join(".env.local"), "OPENAI_API_KEY=sk-guess-111111111111111\n").unwrap();
    assert!(matches!(need::need(&ctx, &g1, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap()[0], need::Outcome::Pending { .. }));
    let g2 = tmp("v2-oracle-g2").canonicalize().unwrap();
    std::fs::write(g2.join(".env.local"), format!("OPENAI_API_KEY={v}\n")).unwrap();
    assert!(matches!(need::need(&ctx, &g2, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap()[0], need::Outcome::Pending { .. }),
        "a miss anywhere closes the check for this key everywhere until the TTL passes");
}

#[test]
fn rotation_with_a_broad_grant_never_writes_a_sensitive_key() {
    let _g = env_lock();
    let (home, proj_a) = v2_world("rot-broad");
    let proj_b = tmp("v2-rot-broad-b").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // A holds STRIPE via a paste; B has a broad grant and once received STRIPE one-time
    let t = tasks::create_secret_task(&ctx, &proj_a, "t", "STRIPE_SECRET_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("sk_live_oldoldoldold".to_string()), true).unwrap();
    let ws_b = db.workspace_for(&proj_b).unwrap();
    db.grant(&ws_b.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    let once = tasks::create_approval_task(&ctx, &proj_b, "run", &["STRIPE_SECRET_KEY@default".to_string()], tasks::ApprovalKind::Once).unwrap();
    tasks::answer_approval(&ctx, &once, tasks::Decision::Allow, None).unwrap();
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("sk_live_old"));
    let card = tasks::rotate(&ctx, &proj_a, "human", "STRIPE_SECRET_KEY", "default").unwrap();
    let r = tasks::answer_secret(&ctx, &card, SecretString::from("sk_live_newnewnewnew".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation: Some(rep), .. } = r else { panic!() };
    assert!(rep.rewritten.is_empty(), "{rep:?}");
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("sk_live_old"), "broad never covers a sensitive key");
    // …but a broad grant does carry a registry non-sensitive key
    let t = tasks::create_secret_task(&ctx, &proj_a, "t", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_oldoldoldoldoldold".to_string()), true).unwrap();
    need::need(&ctx, &proj_b, "t", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    let card = tasks::rotate(&ctx, &proj_a, "human", "GROQ_API_KEY", "default").unwrap();
    let r = tasks::answer_secret(&ctx, &card, SecretString::from("gsk_newnewnewnewnewnew".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation: Some(rep), .. } = r else { panic!() };
    assert_eq!(rep.rewritten, vec![proj_b.to_string_lossy().to_string()], "{rep:?}");
}

#[test]
fn a_denied_run_card_does_not_block_pairing_but_a_denied_pairing_blocks_run() {
    let _g = env_lock();
    let (home, proj) = v2_world("denykinds");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    let once = need::need(&ctx, &proj, "run", &["OPENAI_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    let tid = match &once[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Deny, None).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "a denied run card is not a denied pairing: {out:?}");
    let pid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), _ => unreachable!() };
    tasks::answer_approval(&ctx, &db.get_task(&pid).unwrap().unwrap(), tasks::Decision::Deny, None).unwrap();
    let once = need::need(&ctx, &proj, "run", &["OPENAI_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    assert!(matches!(once[0], need::Outcome::Denied { .. }), "a denied pairing blocks a run request too: {once:?}");
}

#[test]
fn a_card_that_grew_since_it_was_read_is_refused() {
    let _g = env_lock();
    let (home, proj) = v2_world("toctou");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    for n in ["OPENAI_API_KEY", "GROQ_API_KEY"] {
        stash.set(&stash::stash_key(n, "default"), &SecretString::from("aaaaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    }
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let shown = db.get_task(&tid).unwrap().unwrap();
    // the agent asks for more while the human has the page open
    need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let err = tasks::answer_approval(&ctx, &shown, tasks::Decision::Allow, Some(&shown.names)).unwrap_err().to_string();
    assert!(err.contains("changed since you read it"), "{err}");
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.grants_for(&ws.id).unwrap().is_empty());
    // re-read, then it goes through
    let now = db.get_task(&tid).unwrap().unwrap();
    tasks::answer_approval(&ctx, &now, tasks::Decision::Allow, Some(&now.names)).unwrap();
    assert_eq!(db.grants_for(&ws.id).unwrap().len(), 2);
}

#[test]
fn refused_roots_include_home_and_tool_dirs_and_a_dotfiles_repo_is_not_a_project() {
    let _g = env_lock();
    let (home_ts, _proj) = v2_world("refused2");
    let cfg = Config::default();
    let db = Db::open(&home_ts.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let home = dirs::home_dir().unwrap();
    for (p, why) in [(home.clone(), "home directory"), (home.join(".ssh"), "credential directory")] {
        if !p.is_dir() { continue; }
        let err = need::need(&ctx, &p, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap_err().to_string();
        assert!(err.contains(why), "{err}");
    }
    // a `.git` at a refused root does not make its children resolve to it
    let fake_home = tmp("v2-fakehome").canonicalize().unwrap();
    std::fs::create_dir_all(fake_home.join(".git")).unwrap();
    std::fs::create_dir_all(fake_home.join("scratch/foo")).unwrap();
    assert_eq!(envfile::owned_git_root(&fake_home.join("scratch/foo")).unwrap(), Some(fake_home.clone()), "an ordinary dir with .git is a root");
    assert!(trust::refused_root(&home).is_some());
}

#[test]
fn wait_after_a_pairing_card_delivers_with_the_pairing_source() {
    let _g = env_lock();
    let (home, proj) = v2_world("waitpair");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    let mut out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    need::wait(&ctx, &proj, &mut out, std::time::Duration::from_millis(10)).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{out:?}");
    let rows = db.recent_audit(10).unwrap();
    assert!(rows.iter().any(|r| r.3 == "inject" && r.7.as_deref() == Some(db::GRANT_PAIRING)), "{rows:?}");
    assert!(!rows.iter().any(|r| r.3 == "inject" && r.7.as_deref() == Some(db::GRANT_PASTE)));
}

#[test]
fn migration_handles_symlinked_duplicates_and_non_directories() {
    let dir = tmp("v2-migrate2");
    let path = dir.join("old.db");
    let proj = dir.join("proj"); std::fs::create_dir_all(&proj).unwrap();
    let link = dir.join("link"); std::os::unix::fs::symlink(&proj, &link).unwrap();
    let file = dir.join("afile"); std::fs::write(&file, "x").unwrap();
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE approvals (project TEXT NOT NULL, name TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY (project, name));
                         CREATE TABLE bindings (project TEXT NOT NULL, name TEXT NOT NULL, identity TEXT NOT NULL, PRIMARY KEY (project, name));").unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'OPENAI_API_KEY', 't')", [proj.to_string_lossy().to_string()]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'GROQ_API_KEY', 't')", [link.to_string_lossy().to_string()]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'X_KEY', 't')", [file.to_string_lossy().to_string()]).unwrap();
    }
    let db = Db::open(&path).unwrap();
    assert_eq!(db.list_workspaces().unwrap().len(), 1, "the symlink and its target are one workspace; a file is none");
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert_eq!(db.grants_for(&ws.id).unwrap().len(), 2);
}
