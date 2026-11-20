//! Protection: Defender's own health checks, scans in progress, and what it caught.

use rune::tok::{Theme, space, type_};
use rune::{El, TextStyle, col, row, text};

use super::words::{Reading, Tone, age, definitions_fresh, scan_kind};
use super::{dot, fact, grouped, page_title, section};
use crate::state::State;

pub fn page(s: &State, t: Theme, r: &Reading) -> El {
    let sub = match r.protected {
        None => "Asking Defender how it's doing…",
        Some(true) if r.problems.is_empty() => "Your Mac is protected.",
        _ => "Protection needs attention.",
    };
    let mut page = col().w_full().gap(16.0).child(page_title("Protection", sub, t));

    if let Some(h) = &s.health {
        let checks = [
            ("Defender reports itself healthy", h.healthy, String::new()),
            ("Real-time protection is on", !h.passive_mode, String::new()),
            ("Cloud protection is on", h.cloud_enabled, String::new()),
            ("Has Full Disk Access", h.full_disk_access, String::new()),
            ("Threat definitions are up to date", definitions_fresh(h.definitions_age_min), format!("updated {}", age(h.definitions_age_min))),
        ];
        let rows = checks.into_iter().enumerate().map(|(i, (label, ok, note))| {
            row().key(format!("check-{i}")).w_full().min_h(40.0).px(space::S3).center_y().gap(space::S3).children([
                text(if ok { "✓" } else { "!" }).font(TextStyle::new(14.0, 700.0))
                    .color(if ok { Tone::Good.color() } else { Tone::Bad.color() }).w(14.0),
                text(label).font(TextStyle::new(13.5, 500.0)).color(t.text).grow(1.0).min_w(0.0),
                text(note).font(type_::BODY).color(t.text_secondary),
            ])
        }).collect();
        page = page.child(grouped(rows, t));
        let on = |v: &str| matches!(v, "enabled" | "block" | "audit" | "started");
        let say = |v: &str| match v {
            "block" => "On — blocks changes".to_owned(),
            "audit" => "Audit only — logs changes".to_owned(),
            "enabled" | "started" => "On".to_owned(),
            "disabled" | "stopped" => "Off".to_owned(),
            "" | "?" => "Unknown".to_owned(),
            other => other.to_owned(),
        };
        let tags = if h.device_tags.is_empty() { "None".to_owned() } else { h.device_tags.join(", ") };
        page = page.child(section("Defender's settings", t)).child(grouped(vec![
            fact("set-tamper", if on(&h.tamper_protection) { Tone::Good } else { Tone::Warn }, "Tamper protection", say(&h.tamper_protection), t),
            fact("set-behavior", Tone::Neutral, "Behavior monitoring (watches what programs do)", say(&h.behavior_monitoring), t),
            fact("set-network", Tone::Neutral, "Network protection (blocks bad sites)", say(&h.network_protection), t),
            fact("set-dlp", Tone::Neutral, "Data loss prevention", say(&h.dlp), t),
            fact("set-trouble", if h.troubleshooting_mode { Tone::Warn } else { Tone::Good }, "Troubleshooting mode",
                if h.troubleshooting_mode { "On".into() } else { "Off".into() }, t),
            fact("set-tags", Tone::Neutral, "Device tags your employer set", tags, t),
            fact("set-ring", Tone::Neutral, "Update channel", h.release_ring.clone(), t),
        ], t));
        let managed = if h.managed_by.is_empty() || h.managed_by == "?" { String::new() } else { format!(" · managed by {}", h.managed_by) };
        page = page.child(
            text(format!("Defender {} · engine {} · definitions {}{}", h.app_version, h.engine_version, h.definitions_version, managed))
                .font(type_::SECTION).color(t.text_secondary),
        );
    }

    if !s.scans.is_empty() {
        let rows = s.scans.iter().enumerate().map(|(i, scan)| {
            row().key(format!("scan-{i}")).w_full().min_h(40.0).px(space::S3).center_y().gap(space::S3).children([
                dot(crate::classify::Kind::Scan.color(), 8.0),
                text(format!("A scan is {}: {}", scan.status, scan_kind(&scan.kind))).font(type_::BODY).color(t.text),
            ])
        }).collect();
        page = page.child(section("Scans", t)).child(grouped(rows, t));
    }

    page = page.child(section("Threats", t));
    if s.threats.is_empty() {
        page.child(text("Nothing has been found or quarantined.").font(type_::BODY).color(t.text_secondary))
    } else {
        let rows = s.threats.iter().enumerate().map(|(i, th)| {
            row().key(format!("threat-{i}")).w_full().min_h(48.0).px(space::S3).center_y().gap(space::S3).children([
                dot(Tone::Bad.color(), 8.0),
                col().grow(1.0).min_w(0.0).gap(2.0).children([
                    text(th.name.clone()).font(TextStyle::new(13.5, 500.0)).color(t.text).truncate(),
                    text(format!("{} · {}", th.status, th.t)).font(type_::SECTION).color(t.text_secondary),
                ]),
            ])
        }).collect();
        let advice = if s.threats.iter().any(|th| th.is_behavior()) {
            "Behavior detections flag something a command did, not a file. Defender sends them to your \
             employer's security team as alerts, so they have likely seen it. Look at what ran just \
             before the detection time, and tell them before they ask."
        } else {
            "Quarantined files are locked away and can't run. There's nothing you need to do."
        };
        page.child(grouped(rows, t)).child(text(advice).font(type_::BODY).color(t.text_secondary).wrap())
    }
}
