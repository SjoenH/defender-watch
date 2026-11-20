//! The window: a sidebar of pages, in plain language. Overview answers "is everything
//! fine?"; the other pages hold the detail for whoever wants it.

mod activity;
mod chart;
mod explore;
mod management;
mod overview;
mod performance;
mod privacy;
mod protection;
mod words;

use rune::tok::{self, Theme, radius, space, type_};
use rune::{Color, Cx, El, Key, KeyEvent, ScrollSpec, TextStyle, Tx, col, el, oklch, row, text};

use crate::state::{Page, State};
use words::{Reading, Tone};

const SIDEBAR_W: f32 = 200.0;

pub fn view(s: &State, cx: &mut Cx<State>) -> El {
    let dark = cx.system_dark();
    let t = tok::theme(dark);
    let r = Reading::of(s);
    let page = match s.page {
        Page::Overview => overview::page(s, t, &r),
        Page::Performance => performance::page(s, t, &r),
        Page::Privacy => privacy::page(s, t, &r),
        Page::Protection => protection::page(s, t, &r),
        Page::Activity => activity::page(s, t),
        Page::Explore => explore::page(s, t),
        Page::Management => management::page(s, t),
    };
    row().w_full().h_full().fill(t.bg).children([
        sidebar(s, t, dark, &r),
        col().key(format!("page-{:?}", s.page)).grow(1.0).min_w(0.0).h_full()
            .scroll(ScrollSpec { stick_bottom: false })
            .child(col().w_full().max_w(1100.0).padding(space::S6).gap(16.0).child(page)),
    ])
}

/// ⌘1…⌘7 pick a page, as in a Mac app's sidebar.
pub fn on_key(s: &mut State, k: &KeyEvent, _: &mut Tx) -> bool {
    if s.page == Page::Explore && !k.mods.cmd && explore::on_key(s, k) {
        return true;
    }
    for (i, page) in Page::ALL.iter().enumerate() {
        if k.is_command(char::from(b'1' + i as u8)) {
            s.page = *page;
            return true;
        }
    }
    if matches!(k.key, Key::Up | Key::Down) && k.mods.cmd {
        let i = Page::ALL.iter().position(|p| *p == s.page).unwrap_or(0);
        let n = Page::ALL.len();
        s.page = Page::ALL[if k.key == Key::Up { (i + n - 1) % n } else { (i + 1) % n }];
        return true;
    }
    false
}

fn sidebar(s: &State, t: Theme, dark: bool, r: &Reading) -> El {
    let mut nav = col().key("sidebar").w(SIDEBAR_W).h_full().padding(space::S3).gap(2.0)
        .fill(t.card).border_sides([0.0, 1.0, 0.0, 0.0], t.separator)
        .child(text("Defender Watch").font(TextStyle::new(15.0, 680.0)).color(t.text).padding(space::S2))
        .child(el().h(space::S2));
    for page in Page::ALL {
        let on = s.page == page;
        let mut item = row().key(format!("nav-{page:?}")).w_full().h(30.0).px(space::S2).radius(radius::SM)
            .center_y().gap(space::S2)
            .fill(if on { tok::accent(0, dark).alpha(0.16) } else { t.card })
            .hover(t.hover)
            .on_press(move |s: &mut State| s.page = page)
            .child(text(page.title()).font(if on { type_::TITLE } else { type_::BODY }).color(t.text).grow(1.0));
        if page == Page::Protection && (r.threats > 0 || !r.problems.is_empty()) {
            let n = r.threats + r.problems.len();
            item = item.child(
                text(n.to_string()).font(type_::SECTION).color(oklch(1.0, 0.0, 0.0)).px(6.0).radius(8.0).fill(Tone::Bad.color()),
            );
        }
        nav = nav.child(item);
    }
    nav = nav.child(el().grow(1.0));
    if s.demo {
        nav = nav.child(text("Demo data — `cargo run` shows your own Mac").font(type_::SECTION).color(t.text_secondary).wrap().px(space::S2));
    }
    nav
}

// ── Pieces the pages share ──────────────────────────────────────────────────────────────

pub(crate) fn dot(c: Color, size: f32) -> El {
    el().size(size, size).radius(size / 2.0).fill(c)
}

/// A rounded card.
pub(crate) fn panel(t: Theme) -> El {
    col().w_full().min_w(0.0).fill(t.card).radius(radius::LG).border(1.0, t.card_border).padding(16.0).gap(space::S2)
}

pub(crate) fn page_title(title: &str, sub: &str, t: Theme) -> El {
    col().w_full().gap(4.0).children([
        text(title.to_owned()).font(TextStyle::new(22.0, 680.0)).color(t.text),
        text(sub.to_owned()).font(TextStyle::new(13.5, 400.0)).color(t.text_secondary).wrap().min_w(0.0),
    ])
}

pub(crate) fn section(title: &str, t: Theme) -> El {
    text(title.to_owned()).font(type_::TITLE).color(t.text)
}

/// Rows in one card with hairlines between them, as in System Settings.
pub(crate) fn grouped(rows: Vec<El>, t: Theme) -> El {
    let mut c = col().w_full().min_w(0.0).fill(t.card).radius(radius::LG).border(1.0, t.card_border).clip_rounded(radius::LG);
    let n = rows.len();
    for (i, r) in rows.into_iter().enumerate() {
        c = c.child(r);
        if i + 1 < n {
            c = c.child(el().w_full().h(1.0).fill(t.separator));
        }
    }
    c
}

/// A settings-style row: a status dot, a name and a value.
pub(crate) fn fact(key: &str, tone: Tone, title: &str, value: String, t: Theme) -> El {
    row().key(key.to_owned()).w_full().min_h(44.0).px(space::S3).center_y().gap(space::S3).children([
        dot(tone.color(), 10.0),
        text(title.to_owned()).font(TextStyle::new(13.5, 500.0)).color(t.text).grow(1.0).min_w(0.0),
        text(value).font(type_::BODY).color(t.text_secondary),
    ])
}
