//! The `mdatp` command-line interface: health, threats and scan status, as data.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::state::{Health, ScanInfo, Threat};

pub struct Mdatp;

/// launchd starts agents with PATH=/usr/bin:/bin:/usr/sbin:/sbin, which lacks the
/// /usr/local/bin/mdatp symlink, so look in the known places before trusting PATH.
fn program() -> &'static str {
    const KNOWN: [&str; 2] = [
        "/usr/local/bin/mdatp",
        "/Applications/Microsoft Defender.app/Contents/Resources/Tools/wdavdaemonclient",
    ];
    KNOWN.into_iter().find(|p| std::path::Path::new(p).exists()).unwrap_or("mdatp")
}

impl Mdatp {
    fn run(&self, args: &[&str]) -> Option<String> {
        let output = match std::process::Command::new(program()).args(args).output() {
            Ok(output) => output,
            Err(err) => {
                eprintln!("mdatp {}: {err}", args.join(" "));
                return None;
            }
        };
        if !output.status.success() {
            eprintln!("mdatp {}: exit {}", args.join(" "), output.status);
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// `mdatp health --output json`: the product's own self-report.
    pub fn health(&self) -> Option<Health> {
        let json = self.run(&["health", "--output", "json"])?;
        let value: Value = serde_json::from_str(&json).ok()?;
        let edr: Value = self.run(&["health", "--details", "edr", "--output", "json"])
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or(Value::Null);
        Some(health_from(&value, &edr))
    }

    /// `mdatp threat list`: text blocks of `Key: value` lines.
    pub fn threats(&self) -> Vec<Threat> {
        self.try_threats().unwrap_or_default()
    }

    /// Like `threats`, but `None` when `mdatp` could not be asked at all.
    pub fn try_threats(&self) -> Option<Vec<Threat>> {
        self.run(&["threat", "list"]).map(|text| threats_from(&text))
    }

    /// `mdatp scan list`: text blocks of `Key: value` lines; "No scans." when idle.
    pub fn scans(&self) -> Vec<ScanInfo> {
        self.run(&["scan", "list"]).map_or(vec![], |text| scans_from(&text))
    }
}

/// `mdatp health --output json` (and `--details edr`) as data.
pub fn health_from(value: &Value, edr: &Value) -> Health {
    let managed_settings = value.as_object().into_iter().flatten()
        .filter(|(_, v)| v["isManaged"].as_bool() == Some(true))
        .map(|(k, _)| setting_name(k))
        .collect();
    Health {
        app_version: plain(value, "appVersion"),
        definitions_version: plain(value, "definitionsVersion"),
        definitions_age_min: value["definitionsUpdatedMinutesAgo"].as_u64().unwrap_or(0),
        passive_mode: flag(value, "passiveModeEnabled"),
        cloud_enabled: flag(value, "cloudEnabled"),
        cloud_sample_submission: word(value, "cloudAutomaticSampleSubmissionConsent"),
        full_disk_access: value["fullDiskAccessEnabled"].as_bool().unwrap_or(false),
        managed_by: word(value, "managedBy"),
        healthy: value["healthy"].as_bool().unwrap_or(false),
        engine_version: plain(value, "engineVersion"),
        release_ring: plain(value, "releaseRing"),
        tamper_protection: word(value, "tamperProtection"),
        behavior_monitoring: word(value, "behaviorMonitoring"),
        network_protection: word(value, "networkProtectionStatus"),
        dlp: word(value, "dataLossPreventionStatus"),
        troubleshooting_mode: flag(value, "troubleshootingMode"),
        device_tags: value["edrDeviceTags"]["value"].as_array().into_iter().flatten()
            .filter_map(|t| t.as_str().map(str::to_owned).or_else(|| t["value"].as_str().map(str::to_owned)))
            .collect(),
        edr_endpoint: edr["edrCyberEndpoint"].as_str().unwrap_or("").to_owned(),
        edr_geo: edr["edrPreferredGeo"].as_str().unwrap_or("").to_owned(),
        org_id: plain(value, "orgId"),
        machine_id: plain(value, "edrMachineId"),
        managed_settings,
    }
}

/// "cloudAutomaticSampleSubmissionConsent" → "cloud automatic sample submission consent".
fn setting_name(key: &str) -> String {
    let mut out = String::new();
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            out.push(' ');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn threats_from(text: &str) -> Vec<Threat> {
    blocks(text).into_iter().filter_map(threat_from).collect()
}

fn threat_from(block: BTreeMap<String, String>) -> Option<Threat> {
    Some(Threat {
        name: block.get("name")?.clone(),
        t: field(&block, "detection time"),
        status: field(&block, "status"),
    })
}

pub fn scans_from(text: &str) -> Vec<ScanInfo> {
    blocks(text).into_iter().map(scan_from).collect()
}

fn scan_from(block: BTreeMap<String, String>) -> ScanInfo {
    ScanInfo {
        kind: block.get("type").or_else(|| block.get("name")).cloned().unwrap_or_else(|| "scan".into()),
        status: field(&block, "status"),
    }
}

/// `{"value": …}`-style entries: the plain string the product reports.
fn word(value: &Value, key: &str) -> String {
    value[key]["value"].as_str().or_else(|| value[key].as_str()).unwrap_or("?").into()
}

/// A bare field.
fn plain(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or("?").into()
}

/// A `{"value": bool}`-style entry.
fn flag(value: &Value, key: &str) -> bool {
    value[key]["value"].as_bool().or_else(|| value[key].as_bool()).unwrap_or(false)
}

/// Split `Key: value` lines into blocks, one per `Id:`; keys lowercased.
fn blocks(text: &str) -> Vec<BTreeMap<String, String>> {
    let mut blocks = vec![];
    let mut current = BTreeMap::new();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else { continue };
        let key = key.trim().to_lowercase();
        if key == "id" && !current.is_empty() {
            blocks.push(std::mem::take(&mut current));
        }
        current.insert(key, rest.trim().to_owned());
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    blocks
}

fn field(block: &BTreeMap<String, String>, key: &str) -> String {
    block.get(key).map_or_else(|| "?".into(), |v| unquote(v))
}

fn unquote(text: &str) -> String {
    text.trim_matches('"').to_owned()
}

#[cfg(test)]
mod mdatp_tests {
    use super::*;

    #[test]
    fn threat_blocks_parse() {
        let text = "Id: \"00000001\"\nName: Virus:DOS/EICAR_Test_File\nType: \"virus\"\nDetection time: Mon Jan 5 10:00:01 2026\nStatus: \"quarantined\"\n\nId: \"00000002\"\nName: Behavior:MacOS/Example.A\nType: \"behavior\"\nDetection time: Mon Jan 5 10:00:02 2026\nStatus: \"quarantined\"\n";
        let threats = threats_from(text);
        assert_eq!(threats.len(), 2);
        assert_eq!(threats[0].name, "Virus:DOS/EICAR_Test_File");
        assert_eq!(threats[1].status, "quarantined");
        assert_eq!(threats[1].t, "Mon Jan 5 10:00:02 2026");
        assert!(!threats[0].is_behavior() && threats[1].is_behavior());
    }

    #[test]
    fn health_reads_settings_and_who_pins_them() {
        let value: Value = serde_json::from_str(r#"{"healthy":true,"tamperProtection":{"isManaged":false,"value":"block"},
            "realTimeProtectionEnabled":{"isManaged":true,"value":true},"networkProtectionStatus":"stopped",
            "edrDeviceTags":{"value":[]},"releaseRing":"Production"}"#).unwrap_or_default();
        let edr: Value = serde_json::from_str(r#"{"edrCyberEndpoint":"https://winatp-gw-neu.microsoft.com/","edrPreferredGeo":"europe"}"#).unwrap_or_default();
        let h = health_from(&value, &edr);
        assert!(h.healthy);
        assert_eq!(h.tamper_protection, "block");
        assert_eq!(h.network_protection, "stopped");
        assert_eq!(h.edr_geo, "europe");
        assert_eq!(h.managed_settings, vec!["real time protection enabled".to_owned()]);
    }

    #[test]
    fn no_scans_is_no_scans() {
        assert!(scans_from("No scans.").is_empty());
    }

    #[test]
    fn unquote_strips_quotes() {
        assert_eq!(unquote("\"quarantined\""), "quarantined");
    }
}
