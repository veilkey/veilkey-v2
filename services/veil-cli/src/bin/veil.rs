use std::env;
use std::process;

fn find_bin(env_key: &str, name: &str) -> String {
    if let Ok(v) = env::var(env_key) {
        if !v.is_empty() {
            return v;
        }
    }
    // Try PATH lookup
    which(name).unwrap_or_else(|| {
        eprintln!("veil: {} not found (set {} or add to PATH)", name, env_key);
        process::exit(1);
    })
}

fn which(name: &str) -> Option<String> {
    let path = env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let candidate = format!("{}/{}", dir, name);
        if std::path::Path::new(&candidate).exists() {
            return Some(candidate);
        }
    }
    None
}

fn exec_replace(bin: &str, args: &[String]) -> ! {
    use std::os::unix::process::CommandExt;
    let err = process::Command::new(bin).args(args).exec();
    eprintln!("veil: exec {}: {}", bin, err);
    process::exit(1);
}

/// Find and load .veilkey/env
/// Priority: VEILKEY_ENV > walk up from cwd > ~/.veilkey/env > ~/veilkey-selfhosted/.veilkey/env
fn auto_load_env() {
    // 1. Explicit path
    if let Ok(p) = env::var("VEILKEY_ENV") {
        if !p.is_empty() && std::path::Path::new(&p).exists() {
            load_env_file(&p);
            return;
        }
    }

    // 2. Walk up from current dir
    let mut dir = env::current_dir().ok();
    while let Some(d) = &dir {
        let env_file = d.join(".veilkey").join("env");
        if env_file.exists() {
            load_env_file(&env_file.to_string_lossy());
            return;
        }
        dir = d.parent().map(|p| p.to_path_buf());
    }

    // 3. Home fallback paths
    if let Ok(home) = env::var("HOME") {
        for sub in &[".veilkey/env", "veilkey-selfhosted/.veilkey/env"] {
            let p = format!("{}/{}", home, sub);
            if std::path::Path::new(&p).exists() {
                load_env_file(&p);
                return;
            }
        }
    }
}

fn load_env_file(path: &str) {
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() || line.starts_with("#!/") {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"').trim_matches('\'');
                env::set_var(k, v);
            }
        }
    }
}

fn main() {
    // Auto-load .veilkey/env from current or parent dirs
    // Clear legacy env vars first so .veilkey/env takes precedence
    auto_load_env();
    // If VEILKEY_LOCALVAULT_URL is set, ensure VEILKEY_API matches
    if let Ok(url) = env::var("VEILKEY_LOCALVAULT_URL") {
        env::set_var("VEILKEY_API", &url);
    }

    let cli_bin = find_bin("VEILKEY_CLI_BIN", "veilkey-cli");

    env::set_var("VEILKEY_VEIL", "1");
    env::set_var("VEIL_PS1", "(veil) ");

    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        // Create temp rcfile for custom prompt
        let rc_path = format!("{}/veil-bashrc", env::temp_dir().display());
        let rc_content = r#"
[ -f ~/.bashrc ] && source ~/.bashrc
[ -f ~/.bash_profile ] && source ~/.bash_profile
export PS1="\[\033[36m\](VEIL)\[\033[0m\] \h:\W \u\$ "
"#;
        let _ = std::fs::write(&rc_path, rc_content);

        // veil → enter protected shell with custom prompt
        exec_replace(
            &cli_bin,
            &["wrap-pty".to_string(), "bash".to_string(), "--rcfile".to_string(), rc_path],
        );
    }

    match args[0].as_str() {
        "status" => {
            exec_replace(&cli_bin, &["status".to_string()]);
        }
        "resolve" => {
            let mut full = vec!["resolve".to_string()];
            full.extend_from_slice(&args[1..]);
            exec_replace(&cli_bin, &full);
        }
        "exec" => {
            let mut full = vec!["exec".to_string()];
            full.extend_from_slice(&args[1..]);
            exec_replace(&cli_bin, &full);
        }
        "scan" => {
            let mut full = vec!["scan".to_string()];
            full.extend_from_slice(&args[1..]);
            exec_replace(&cli_bin, &full);
        }
        "help" | "-h" | "--help" => {
            println!("Usage:");
            println!("  veil                     Enter protected session (PTY masking)");
            println!("  veil status              Show VeilKey connection status");
            println!("  veil resolve <VK:ref>    Resolve a VK reference");
            println!("  veil exec <command...>   Resolve VK refs in args and execute");
            println!("  veil scan [file...]      Scan files for secrets");
            println!("  veil help                Show this help");
        }
        _ => {
            // Pass through to wrap-pty with args as command
            let mut full = vec!["wrap-pty".to_string()];
            full.extend_from_slice(&args);
            exec_replace(&cli_bin, &full);
        }
    }
}
