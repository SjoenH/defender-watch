//! Management: what the employer's device management (Intune) has installed on this Mac,
//! and what each piece lets them do, in words.

use rune::tok::{Theme, space, type_};
use rune::{El, TextStyle, col, row, text};

use super::words::Tone;
use super::{dot, fact, grouped, page_title, panel, section};
use crate::managed::Reach;
use crate::state::State;

fn reach_tone(r: Reach) -> Tone {
    match r {
        Reach::High => Tone::Warn,
        Reach::Medium => Tone::Neutral,
        Reach::Low => Tone::Good,
    }
}

pub fn page(s: &State, t: Theme) -> El {
    let head = page_title(
        "Management",
        "What your employer's device management (Microsoft Intune) has set up on this Mac, and what it lets them do. Read from the profiles macOS lists in System Settings › Device Management.",
        t,
    );
    let Some(m) = &s.managed else {
        return col().w_full().gap(16.0).children([head, text("Reading installed profiles…").font(type_::BODY).color(t.text_secondary)]);
    };
    let employer: Vec<_> = m.profiles.iter().filter(|p| p.employer()).collect();
    let own = m.profiles.len() - employer.len();
    let high = m.powers.iter().filter(|p| p.reach == Reach::High).count();

    let how = if !m.enrollment.enrolled {
        "Not enrolled".to_owned()
    } else if m.enrollment.dep {
        "Automatically (Apple Business Manager)".to_owned()
    } else {
        "You approved it".to_owned()
    };
    let enrollment = grouped(vec![
        fact("mg-enrolled", if m.enrollment.enrolled { Tone::Warn } else { Tone::Good }, "Enrolled in device management", how, t),
        fact("mg-server", Tone::Neutral, "Managed from",
            if m.enrollment.server.contains("manage.microsoft.com") { format!("Microsoft Intune ({})", m.enrollment.server) } else { m.enrollment.server.clone() }, t),
        fact("mg-profiles", Tone::Neutral, "Profiles from your employer",
            format!("{}{}", employer.len(), if own > 0 { format!(" · plus {own} of your own (Screen Time)") } else { String::new() }), t),
        fact("mg-locked", Tone::Neutral, "Locked so you can't remove them",
            format!("{} of {}", employer.iter().filter(|p| p.locked).count(), employer.len()), t),
    ], t);

    let summary = panel(t).key("mg-summary").fill(Tone::Warn.color().alpha(0.10)).children([
        text(format!("{high} of these give your employer deep access")).font(TextStyle::new(15.0, 620.0)).color(t.text),
        text("That's normal for a work Mac, and it's why it's safest to treat everything on it — files, traffic and every command you run — as visible to your employer's IT and security team.")
            .font(type_::BODY).color(t.text).wrap().min_w(0.0),
    ]);

    let powers: Vec<El> = m.powers.iter().enumerate().map(|(i, p)| {
        let tone = reach_tone(p.reach);
        let tag = match p.reach { Reach::High => "Deep access", Reach::Medium => "Shapes the Mac", Reach::Low => "Housekeeping" };
        row().key(format!("power-{i}")).w_full().min_h(56.0).px(space::S3).py(8.0).gap(space::S3).children([
            col().pt(5.0).child(dot(tone.color(), 10.0)),
            col().grow(1.0).min_w(0.0).gap(3.0).children([
                row().w_full().gap(space::S2).center_y().children([
                    text(p.title.clone()).font(TextStyle::new(13.5, 600.0)).color(t.text).grow(1.0).min_w(0.0),
                    text(tag).font(type_::SECTION).color(tone.color()),
                ]),
                text(p.detail.clone()).font(type_::BODY).color(t.text_secondary).wrap().min_w(0.0),
            ]),
        ])
    }).collect();

    let profiles: Vec<El> = employer.iter().enumerate().map(|(i, p)| {
        let kinds = p.payloads.iter().map(|x| x.trim_start_matches("com.apple.").to_owned()).collect::<Vec<_>>().join(", ");
        row().key(format!("profile-{i}")).w_full().min_h(48.0).px(space::S3).py(6.0).center_y().gap(space::S3).children([
            col().grow(1.0).min_w(0.0).gap(2.0).children([
                text(p.name.clone()).font(TextStyle::new(13.5, 500.0)).color(t.text).truncate(),
                text(kinds).font(type_::MONO_CAPTION.mono()).color(t.text_secondary).truncate(),
            ]),
            text(format!("{} · {}", p.source, p.installed)).font(type_::SECTION).color(t.text_secondary),
            text(if p.locked { "Locked" } else { "Removable" }).font(type_::LABEL)
                .color(if p.locked { t.text_secondary } else { Tone::Neutral.color() }).w(76.0).align(rune::Align::End),
        ])
    }).collect();

    let mut page = col().w_full().gap(16.0).children([head, enrollment, summary, section("What it lets them do", t), grouped(powers, t)]);
    if let Some(h) = &s.health {
        let mut rows = vec![
            fact("mg-tenant", Tone::Neutral, "Defender reports to",
                if h.edr_endpoint.is_empty() { "your employer's tenant".into() } else {
                    let host = h.edr_endpoint.trim_start_matches("https://").trim_end_matches('/').to_owned();
                    if h.edr_geo.is_empty() { host } else { format!("{host} · data kept in {}", capitalise(&h.edr_geo)) }
                }, t),
        ];
        if !h.machine_id.is_empty() && h.machine_id != "?" {
            rows.push(fact("mg-device", Tone::Neutral, "This Mac's ID in their console", h.machine_id.clone(), t));
        }
        if !h.org_id.is_empty() && h.org_id != "?" {
            rows.push(fact("mg-org", Tone::Neutral, "Your employer's tenant ID", h.org_id.clone(), t));
        }
        if !h.managed_settings.is_empty() {
            rows.push(fact("mg-pinned", Tone::Neutral, "Defender settings your employer pins", h.managed_settings.join(", "), t));
        }
        page = page.child(section("Defender in your employer's tenant", t)).child(grouped(rows, t));
    }
    page.child(section(&format!("Installed profiles ({})", employer.len()), t)).child(grouped(profiles, t))
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
}
