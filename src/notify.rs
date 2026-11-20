//! `--notify`: a headless watcher, run by launchd, that tells you the moment Defender
//! records a detection, without the dashboard open.
//!
//! Every 30 seconds it asks `mdatp threat list`, compares against the detections it has
//! already seen, and for each new one:
//! - shows a macOS notification and a critical alert that stays until dismissed;
//! - pushes to Pushover, if `~/.config/defender-watch/pushover.conf` exists. That file is
//!   a curl config (`form-string = "token=…"`, `form-string = "user=…"`, mode 600), so
//!   the keys never appear in a command line — Defender logs every one.
//!
//! On the first run it records what is already there without announcing it.
//!
//! `--install-notify` writes a LaunchAgent that keeps `--notify` running at login;
//! `--uninstall-notify` removes it.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::mdatp::Mdatp;
use crate::state::Threat;

const LABEL: &str = "no.koka.defender-watch.notify";
const EVERY: Duration = Duration::from_secs(30);

fn home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from)
}

fn seen_file() -> PathBuf {
    home().join("Library/Application Support/defender-watch/seen-detections.txt")
}

fn pushover_conf() -> PathBuf {
    home().join(".config/defender-watch/pushover.conf")
}

fn plist() -> PathBuf {
    home().join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

fn key(threat: &Threat) -> String {
    format!("{}|{}", threat.name, threat.t)
}

pub fn run() {
    let path = seen_file();
    let first_run = !path.exists();
    let mut seen: BTreeSet<String> = std::fs::read_to_string(&path)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    eprintln!("defender-watch --notify: watching ({} detections already seen)", seen.len());

    let mdatp = Mdatp;
    let mut first = first_run;
    loop {
        let Some(threats) = mdatp.try_threats() else {
            std::thread::sleep(EVERY);
            continue;
        };
        let fresh: Vec<&Threat> = threats.iter().filter(|t| !seen.contains(&key(t))).collect();
        if !fresh.is_empty() {
            if !first {
                announce(&fresh);
            }
            seen.extend(fresh.iter().map(|t| key(t)));
            let text: String = seen.iter().map(|k| format!("{k}\n")).collect();
            if let Err(err) = std::fs::write(&path, text) {
                eprintln!("could not save {}: {err}", path.display());
            }
        }
        first = false;
        std::thread::sleep(EVERY);
    }
}

fn announce(fresh: &[&Threat]) {
    let behavior = fresh.iter().any(|t| t.is_behavior());
    let names: Vec<String> = fresh.iter().map(|t| format!("{} ({}, {})", t.name, t.status, t.t)).collect();
    let title = if behavior { "Defender flagged suspicious behavior" } else { "Defender found a threat" };
    let advice = if behavior {
        "Your employer's security team has likely been alerted. Check what ran just before this, \
         and tell them before they ask."
    } else {
        "Quarantined files can't run."
    };
    let message = format!("{}\n\n{advice}", names.join("\n"));
    eprintln!("{title}: {}", names.join("; "));

    // Text goes in as osascript arguments, never spliced into the script.
    let notification = "on run argv\n display notification (item 2 of argv) with title (item 1 of argv) sound name \"Basso\"\nend run";
    spawn(Command::new("osascript").args(["-e", notification, title, &message]));
    let alert = "on run argv\n display alert (item 1 of argv) message (item 2 of argv) as critical\nend run";
    spawn(Command::new("osascript").args(["-e", alert, title, &message]));

    let conf = pushover_conf();
    if conf.exists() {
        let status = Command::new("curl")
            .arg("-fsS")
            .arg("--config")
            .arg(&conf)
            .args(["--form-string", &format!("title={title}")])
            .args(["--form-string", &format!("message={message}")])
            .args(["--form-string", if behavior { "priority=1" } else { "priority=0" }])
            .arg("https://api.pushover.net/1/messages.json")
            .stdout(Stdio::null())
            .status();
        if !matches!(status, Ok(s) if s.success()) {
            eprintln!("Pushover push failed: {status:?}");
        }
    }
}

/// Start without waiting: `display alert` blocks until it is dismissed.
fn spawn(command: &mut Command) {
    if let Err(err) = command.stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        eprintln!("osascript failed: {err}");
    }
}

fn uid() -> String {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

pub fn install() {
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(exe) => exe,
        Err(err) => return eprintln!("cannot find this program's path: {err}"),
    };
    let log = home().join("Library/Logs/defender-watch-notify.log");
    let plist_text = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{exe}</string><string>--notify</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        exe = exe.display(),
        log = log.display(),
    );
    let path = plist();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(err) = std::fs::write(&path, plist_text) {
        return eprintln!("could not write {}: {err}", path.display());
    }
    let domain = format!("gui/{}", uid());
    let _ = Command::new("launchctl").args(["bootout", &format!("{domain}/{LABEL}")]).stderr(Stdio::null()).status();
    match Command::new("launchctl").arg("bootstrap").arg(&domain).arg(&path).status() {
        Ok(s) if s.success() => {
            println!("Installed: notifications on every new Defender detection.");
            println!("Agent: {}", path.display());
            println!("Log:   {}", log.display());
            if !pushover_conf().exists() {
                println!("Phone push: put a curl config with Pushover's token and user in {}", pushover_conf().display());
            }
        }
        other => eprintln!("launchctl bootstrap failed: {other:?}"),
    }
}

pub fn uninstall() {
    let domain = format!("gui/{}", uid());
    let _ = Command::new("launchctl").args(["bootout", &format!("{domain}/{LABEL}")]).status();
    let _ = std::fs::remove_file(plist());
    println!("Removed the notification agent.");
}
