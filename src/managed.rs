//! What the employer's device management (Intune, via Apple MDM) has put on this Mac, and
//! what each piece lets them do.
//!
//! Everything here is readable without admin rights:
//! - `profiles status -type enrollment`: whether and where the Mac is enrolled;
//! - `system_profiler SPConfigurationProfileDataType -json`: every installed profile and
//!   the kinds of settings (payloads) it carries;
//! - `/Library/Managed Preferences/*.plist`: the settings those profiles enforce.
//!
//! `powers` turns that into plain-language statements, which are what the page shows.

use std::collections::BTreeMap;

use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Enrollment {
    pub enrolled: bool,
    /// The MDM server's host, e.g. "i.manage.microsoft.com".
    pub server: String,
    /// Enrolled automatically through Apple Business Manager (DEP), not by the user.
    pub dep: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub name: String,
    /// How it got here: "MDM", "Manual", "ScreenTime", …
    pub source: String,
    /// The profile can't be removed by the user.
    pub locked: bool,
    /// "2026-10-23".
    pub installed: String,
    /// Payload types, e.g. "com.apple.security.firewall".
    pub payloads: Vec<String>,
}

impl Profile {
    /// Put here by the employer: pushed by MDM, or the enrollment profile itself.
    /// Screen Time's own profiles are the user's.
    pub fn employer(&self) -> bool {
        self.source == "MDM" || self.payloads.iter().any(|p| p == "com.apple.mdm")
    }
}

/// How much a power gives the employer over this Mac and what's on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reach {
    /// Can see or change what's yours: files, traffic, the disk, the whole Mac.
    High,
    /// Shapes how the Mac behaves or what it trusts.
    Medium,
    /// Housekeeping.
    Low,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Power {
    pub reach: Reach,
    pub title: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Managed {
    pub enrollment: Enrollment,
    pub profiles: Vec<Profile>,
    pub powers: Vec<Power>,
}

impl Managed {
    pub fn from_parts(enrollment: Enrollment, profiles: Vec<Profile>, prefs: &BTreeMap<String, Value>) -> Managed {
        let powers = powers(&enrollment, &profiles, prefs);
        Managed { enrollment, profiles, powers }
    }
}

// ── Reading (macOS) ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
pub fn read() -> Option<Managed> {
    let enrollment = run("/usr/bin/profiles", &["status", "-type", "enrollment"]).map(|t| enrollment_from(&t)).unwrap_or_default();
    let profiles = read_profiles()?;
    Some(Managed::from_parts(enrollment, profiles, &read_prefs()))
}

#[cfg(target_os = "macos")]
pub fn read_profiles() -> Option<Vec<Profile>> {
    run("/usr/sbin/system_profiler", &["SPConfigurationProfileDataType", "-json"]).map(|t| profiles_from(&t))
}

/// Every enforced preference domain, as JSON. Device-wide only: the per-user folder
/// repeats them.
#[cfg(target_os = "macos")]
fn read_prefs() -> BTreeMap<String, Value> {
    let dir = std::path::Path::new("/Library/Managed Preferences");
    let mut prefs = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return prefs };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(domain) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".plist")) else { continue };
        let Some(path_str) = path.to_str() else { continue };
        if let Some(json) = run("/usr/bin/plutil", &["-convert", "json", "-o", "-", path_str]) {
            if let Ok(value) = serde_json::from_str(&json) {
                prefs.insert(domain.to_owned(), value);
            }
        }
    }
    prefs
}

#[cfg(target_os = "macos")]
fn run(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

// ── Parsing ─────────────────────────────────────────────────────────────────────────────

/// `profiles status -type enrollment`:
/// ```text
/// Enrolled via DEP: No
/// MDM enrollment: Yes (User Approved)
/// MDM server: https://i.manage.microsoft.com/DeviceGatewayProxy/…
/// ```
pub fn enrollment_from(text: &str) -> Enrollment {
    let mut e = Enrollment::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match key.trim() {
            "Enrolled via DEP" => e.dep = value.starts_with("Yes"),
            "MDM enrollment" => e.enrolled = value.starts_with("Yes"),
            "MDM server" => {
                let rest = value.split_once("://").map_or(value, |(_, r)| r);
                e.server = rest.split('/').next().unwrap_or(rest).to_owned();
            }
            _ => {}
        }
    }
    e
}

/// `system_profiler SPConfigurationProfileDataType -json`: scopes (user, device), each
/// holding profiles, each holding payloads.
pub fn profiles_from(json: &str) -> Vec<Profile> {
    let Ok(value) = serde_json::from_str::<Value>(json) else { return vec![] };
    let mut out = vec![];
    for scope in value["SPConfigurationProfileDataType"].as_array().into_iter().flatten() {
        for p in scope["_items"].as_array().into_iter().flatten() {
            let payloads: Vec<String> = p["_items"].as_array().into_iter().flatten()
                .filter_map(|x| x["_name"].as_str().map(str::to_owned))
                .collect();
            let mut name = p["_name"].as_str().unwrap_or("").trim().to_owned();
            if name.is_empty() {
                name = payloads.first().cloned().unwrap_or_else(|| "(unnamed)".into());
            }
            out.push(Profile {
                name,
                source: p["spconfigprofile_install_source"].as_str().unwrap_or("?").to_owned(),
                locked: p["spconfigprofile_RemovalDisallowed"].as_str() == Some("yes"),
                installed: iso_date(p["spconfigprofile_install_date"].as_str().unwrap_or("")),
                payloads,
            });
        }
    }
    out
}

/// The install date is localised ("fredag 23. oktober 2026 kl. 11:18:02 … (2026-10-23
/// 09:18:02 +0000)"); the ISO date in parentheses is the part every locale shares.
fn iso_date(text: &str) -> String {
    text.rsplit_once('(').map_or_else(String::new, |(_, rest)| rest.chars().take(10).collect())
}

// ── What it all means ───────────────────────────────────────────────────────────────────

/// Plain-language names for privacy permissions (TCC services) a profile can grant.
fn tcc_name(service: &str) -> (&'static str, Reach) {
    match service {
        "SystemPolicyAllFiles" => ("Full Disk Access", Reach::High),
        "Accessibility" => ("control of the Mac (Accessibility)", Reach::High),
        "ScreenCapture" => ("screen recording", Reach::High),
        "ListenEvent" => ("input monitoring (keystrokes)", Reach::High),
        "PostEvent" => ("sending keystrokes", Reach::High),
        "AppleEvents" => ("controlling other apps", Reach::Medium),
        "SystemPolicySysAdminFiles" => ("admin files", Reach::Medium),
        "Camera" => ("the camera", Reach::High),
        "Microphone" => ("the microphone", Reach::High),
        _ => ("a privacy permission", Reach::Medium),
    }
}

/// What a known system extension does, in words.
fn extension_role(id: &str) -> String {
    match id {
        "com.microsoft.wdav.epsext" => "Defender's Endpoint Security extension (sees every program start, file open and login)".into(),
        "com.microsoft.wdav.netext" => "Defender's network extension (sees every network connection)".into(),
        other => other.to_owned(),
    }
}

fn app_name(id: &str) -> String {
    match id {
        "com.microsoft.wdav" => "Microsoft Defender".into(),
        "com.microsoft.wdav.epsext" => "Defender's Endpoint Security extension".into(),
        "com.microsoft.wdav.netext" => "Defender's network extension".into(),
        "com.microsoft.wdav.tray" => "Defender's menu bar icon".into(),
        "com.microsoft.autoupdate2" => "Microsoft AutoUpdate".into(),
        "com.microsoft.CompanyPortalMac" => "Company Portal".into(),
        other => other.to_owned(),
    }
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)).collect()
}

fn hosts(urls: &[String]) -> Vec<String> {
    urls.iter().map(|u| {
        let rest = u.split_once("://").map_or(u.as_str(), |(_, r)| r);
        rest.split('/').next().unwrap_or(rest).to_owned()
    }).collect()
}

/// What the enrollment and the employer's profiles let them do, most far-reaching first.
pub fn powers(enrollment: &Enrollment, profiles: &[Profile], prefs: &BTreeMap<String, Value>) -> Vec<Power> {
    let employer: Vec<&Profile> = profiles.iter().filter(|p| p.employer()).collect();
    let count = |t: &str| employer.iter().flat_map(|p| &p.payloads).filter(|x| *x == t).count();
    let has = |t: &str| count(t) > 0;
    let pref = |domain: &str| prefs.get(domain).unwrap_or(&Value::Null);
    let mut out = vec![];
    let mut add = |reach: Reach, title: &str, detail: String| out.push(Power { reach, title: title.into(), detail });

    if enrollment.enrolled || has("com.apple.mdm") {
        let server = if enrollment.server.is_empty() { String::new() } else { format!(" Server: {}.", enrollment.server) };
        add(Reach::High, "Manages this Mac remotely",
            format!("Can install and remove apps, settings and certificates without asking, and lock or erase the Mac.{server}"));
    }

    if has("com.apple.security.FDERecoveryKeyEscrow") {
        add(Reach::High, "Holds your disk's recovery key",
            "FileVault is on, and its recovery key is sent to your employer, so they can unlock the disk without your password.".into());
    } else if has("com.apple.MCX.FileVault2") {
        add(Reach::Low, "Requires disk encryption", "FileVault must be on.".into());
    }

    if has("com.apple.TCC.configuration-profile-policy") {
        let services = pref("com.apple.TCC.configuration-profile-policy")["Services"].as_object().cloned().unwrap_or_default();
        if services.is_empty() {
            add(Reach::High, "Grants apps privacy permissions without asking",
                "A privacy profile pre-approves access that would otherwise need your OK.".into());
        }
        for (service, rules) in services {
            let allowed: Vec<String> = rules.as_array().into_iter().flatten()
                .filter(|r| r["Allowed"].as_i64() == Some(1) || r["Allowed"].as_bool() == Some(true)
                    || r["Authorization"].as_str() == Some("Allow"))
                .filter_map(|r| r["Identifier"].as_str().map(app_name))
                .collect();
            if allowed.is_empty() {
                continue;
            }
            let (what, reach) = tcc_name(&service);
            let extra = if service == "SystemPolicyAllFiles" {
                " They can read every file on the Mac, including mail, messages and other apps' data."
            } else {
                ""
            };
            add(reach, &format!("Gave {what} without asking you"), format!("To: {}.{extra}", allowed.join(", ")));
        }
    }

    if has("com.apple.webcontent-filter") {
        add(Reach::High, "Filters network traffic",
            "A content filter (Defender's network extension) is installed for every app's connections.".into());
    }

    if has("com.apple.system-extension-policy") {
        let allowed = pref("com.apple.system-extension-policy")["AllowedSystemExtensions"].as_object().cloned().unwrap_or_default();
        let ids: Vec<String> = allowed.values().flat_map(strings).map(|id| extension_role(&id)).collect();
        let detail = if ids.is_empty() {
            "System extensions run with deep access to the Mac; these were approved for you.".into()
        } else {
            format!("Approved for you: {}.", ids.join("; "))
        };
        add(Reach::High, "Pre-approved system extensions", detail);
    }

    let roots = count("com.apple.security.root");
    if roots > 0 {
        add(Reach::Medium, &format!("Added {roots} trusted root certificate{}", if roots == 1 { "" } else { "s" }),
            "Your Mac now trusts certificates these vouch for. Intune uses them for its own connection; a root like this could \
             also vouch for any website, which is what HTTPS inspection relies on. Nothing here shows that happening.".into());
    }

    if has("com.apple.extensiblesso") {
        let urls = hosts(&strings(&pref("com.apple.extensiblesso")["URLs"]));
        let urls = if urls.is_empty() { String::new() } else { format!(" ({})", urls.into_iter().take(2).collect::<Vec<_>>().join(", ")) };
        add(Reach::Medium, "Handles your Microsoft sign-ins",
            format!("Microsoft logins{urls} go through Company Portal, which signs them with this Mac's identity so conditional access can check it."));
    }

    if has("com.microsoft.wdav") || has("com.microsoft.wdav.atp") {
        let wdav = pref("com.microsoft.wdav");
        let mut set = vec![];
        if wdav["cloudService"]["enabled"].as_bool() == Some(true) { set.push("cloud protection on"); }
        if wdav["cloudService"]["automaticSampleSubmission"].as_bool() == Some(true) { set.push("files may be uploaded automatically"); }
        if wdav["antivirusEngine"]["enableRealTimeProtection"].as_bool() == Some(true) { set.push("real-time scanning on"); }
        let overrides = match pref("com.microsoft.wdav.atp")["AllowUserOverrides"].as_bool() {
            Some(true) => " You may change what isn't set here.",
            Some(false) => " You can't change any of it.",
            None => "",
        };
        let what = if set.is_empty() { String::new() } else { format!(": {}", set.join(", ")) };
        add(Reach::Medium, "Sets Defender's settings", format!("Defender is enrolled in your employer's tenant{what}.{overrides}"));
    }

    if count("com.apple.applicationaccess") > 0 {
        let blocked = strings(&pref("com.apple.applicationaccess")["blacklistedAppBundleIDs"]);
        if !blocked.is_empty() {
            add(Reach::Medium, "Blocks apps", format!("Can't open: {}.", blocked.join(", ")));
        }
    }

    if has("com.apple.security.acme") || has("com.apple.security.pkcs1") || has("com.apple.security.scep") {
        add(Reach::Low, "Gave the Mac a device certificate", "Proves to Microsoft that this is the managed Mac.".into());
    }

    if has("com.apple.servicemanagement") {
        let rules: Vec<String> = pref("com.apple.servicemanagement")["Rules"].as_array().into_iter().flatten()
            .filter_map(|r| r["RuleValue"].as_str().map(str::to_owned)).collect();
        let which = if rules.is_empty() { String::new() } else { format!(" ({})", rules.join(", ")) };
        add(Reach::Low, "Locked background items on", format!("You can't switch these off in Login Items{which}."));
    }

    if has("com.apple.security.firewall") {
        add(Reach::Low, "Requires the firewall", "The macOS firewall must stay on.".into());
    }

    if pref("com.microsoft.autoupdate2")["SendAllTelemetryEnabled"].as_bool() == Some(true) {
        add(Reach::Low, "Office updater sends full telemetry", "Microsoft AutoUpdate reports everything it may.".into());
    }

    if has("com.apple.notificationsettings") {
        let apps: Vec<String> = pref("com.apple.notificationsettings")["NotificationSettings"].as_array().into_iter().flatten()
            .filter_map(|n| n["BundleIdentifier"].as_str().map(app_name)).collect();
        let which = if apps.is_empty() { String::new() } else { format!(": {}", apps.join(", ")) };
        add(Reach::Low, "Set how some apps notify you", format!("Notifications forced on{which}."));
    }

    out.sort_by_key(|p| p.reach);
    out
}

#[cfg(test)]
mod managed_tests {
    use super::*;
    use serde_json::json;

    fn profile(name: &str, source: &str, payloads: &[&str]) -> Profile {
        Profile {
            name: name.into(),
            source: source.into(),
            locked: source == "MDM",
            installed: "2026-10-23".into(),
            payloads: payloads.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn enrollment_parses() {
        let e = enrollment_from("Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\nMDM server: https://i.manage.microsoft.com/DeviceGatewayProxy/ioshandler.ashx?Platform=MacMDM\n");
        assert!(e.enrolled);
        assert!(!e.dep);
        assert_eq!(e.server, "i.manage.microsoft.com");
        assert_eq!(enrollment_from("MDM enrollment: No"), Enrollment::default());
    }

    #[test]
    fn profiles_parse_with_iso_dates() {
        let json = r#"{"SPConfigurationProfileDataType":[{"_name":"device","_items":[
            {"_name":"FileVault Profile","spconfigprofile_install_source":"MDM","spconfigprofile_RemovalDisallowed":"yes",
             "spconfigprofile_install_date":"fredag 23. oktober 2026 kl. 11:18:38 (2026-10-23 09:18:38 +0000)",
             "_items":[{"_name":"com.apple.MCX.FileVault2"}]},
            {"_name":"","spconfigprofile_install_source":"ScreenTime","spconfigprofile_RemovalDisallowed":"no",
             "_items":[{"_name":"com.apple.applicationaccess"}]}]}]}"#;
        let p = profiles_from(json);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].installed, "2026-10-23");
        assert!(p[0].locked && p[0].employer());
        assert_eq!(p[1].name, "com.apple.applicationaccess");
        assert!(!p[1].employer());
        assert!(profiles_from("not json").is_empty());
    }

    #[test]
    fn powers_explain_what_profiles_allow() {
        let profiles = vec![
            profile("Management Profile", "Manual", &["com.apple.mdm", "com.apple.security.root", "com.apple.security.root"]),
            profile("FileVault Escrow", "MDM", &["com.apple.security.FDERecoveryKeyEscrow"]),
            profile("fulldisk", "MDM", &["com.apple.TCC.configuration-profile-policy"]),
            profile("Screen Time", "ScreenTime", &["com.apple.applicationaccess"]),
        ];
        let mut prefs = BTreeMap::new();
        prefs.insert("com.apple.TCC.configuration-profile-policy".to_owned(), json!({
            "Services": {"SystemPolicyAllFiles": [{"Allowed": 1, "Identifier": "com.microsoft.wdav"}]}
        }));
        prefs.insert("com.apple.applicationaccess".to_owned(), json!({"blacklistedAppBundleIDs": ["com.example.game"]}));
        let e = Enrollment { enrolled: true, server: "i.manage.microsoft.com".into(), dep: false };
        let powers = powers(&e, &profiles, &prefs);
        let titles: Vec<&str> = powers.iter().map(|p| p.title.as_str()).collect();
        assert!(titles.contains(&"Manages this Mac remotely"));
        assert!(titles.contains(&"Holds your disk's recovery key"));
        assert!(titles.contains(&"Gave Full Disk Access without asking you"));
        assert!(titles.contains(&"Added 2 trusted root certificates"));
        // Screen Time's app limits are the user's own, not the employer's.
        assert!(!titles.contains(&"Blocks apps"));
        assert!(powers.windows(2).all(|w| w[0].reach <= w[1].reach));
        let fda = powers.iter().find(|p| p.title.contains("Full Disk")).map(|p| p.detail.clone()).unwrap_or_default();
        assert!(fda.contains("Microsoft Defender"));
    }
}
