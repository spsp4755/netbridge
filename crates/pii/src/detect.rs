use chrono::NaiveDate;
use netbridge_proto::{PiiAction, PiiHit, PiiRule};
use regex::Regex;
use std::ops::Range;
use std::sync::OnceLock;

struct Builtins {
    rrn: Regex,
    phone: Regex,
    card: Regex,
    account: Regex,
    passport: Regex,
    driver: Regex,
    email: Regex,
}

fn builtins() -> &'static Builtins {
    static B: OnceLock<Builtins> = OnceLock::new();
    B.get_or_init(|| Builtins {
        rrn: Regex::new(r"(\d{6})-?([1-8])\d{6}").unwrap(),
        phone: Regex::new(r"01[016789]-?\d{3,4}-?\d{4}").unwrap(),
        card: Regex::new(r"\d{4}[- ]?\d{6}[- ]?\d{5}|\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7}").unwrap(),
        account: Regex::new(r"\d{3,6}-\d{2,6}-\d{2,6}(?:-\d{1,3})?").unwrap(),
        passport: Regex::new(r"[MSRODG](?:\d{8}|\d{3}[A-Z]\d{4})").unwrap(),
        driver: Regex::new(r"\d{2}-\d{2}-\d{6}-\d{2}").unwrap(),
        email: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
    })
}

/// The regex crate has no look-around, so boundaries are checked by hand.
fn bounded(text: &str, r: &Range<usize>, alnum: bool) -> bool {
    let bad = |c: char| if alnum { c.is_ascii_alphanumeric() } else { c.is_ascii_digit() };
    let before = text[..r.start].chars().next_back().map_or(true, |c| !bad(c));
    let after = text[r.end..].chars().next().map_or(true, |c| !bad(c));
    before && after
}

fn find(re: &Regex, text: &str, alnum: bool, ok: impl Fn(&str) -> bool) -> Vec<Range<usize>> {
    re.find_iter(text).map(|m| m.range()).filter(|r| bounded(text, r, alnum) && ok(&text[r.clone()])).collect()
}

fn rrn_ok(s: &str) -> bool {
    let d: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let century = match d.as_bytes()[6] {
        b'1' | b'2' | b'5' | b'6' => 1900,
        _ => 2000,
    };
    let y: i32 = d[0..2].parse().unwrap();
    let m: u32 = d[2..4].parse().unwrap();
    let day: u32 = d[4..6].parse().unwrap();
    // No checksum check: numbers issued since Oct 2020 have random trailing digits.
    NaiveDate::from_ymd_opt(century + y, m, day).is_some()
}

fn luhn_ok(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| if i % 2 == 1 { let y = x * 2; if y > 9 { y - 9 } else { y } } else { x })
        .sum();
    sum % 10 == 0
}

fn overlaps(r: &Range<usize>, taken: &[Range<usize>]) -> bool {
    taken.iter().any(|t| r.start < t.end && t.start < r.end)
}

/// Matches per rule id, in rule order. Builtin numeric rules claim spans so a
/// phone number is not also counted as an account number.
fn matches(text: &str, rules: &[PiiRule]) -> Vec<(String, Vec<Range<usize>>)> {
    let b = builtins();
    let rrn = find(&b.rrn, text, false, rrn_ok);
    let card = find(&b.card, text, false, luhn_ok);
    let driver = find(&b.driver, text, false, |_| true);
    let phone = find(&b.phone, text, false, |_| true);
    let mut taken: Vec<Range<usize>> = [&rrn, &card, &driver, &phone].iter().flat_map(|v| v.iter().cloned()).collect();
    let account: Vec<_> = find(&b.account, text, false, |_| true).into_iter().filter(|r| !overlaps(r, &taken)).collect();
    taken.extend(account.iter().cloned());
    let passport = find(&b.passport, text, true, |_| true);
    let email = find(&b.email, text, false, |_| true);

    rules
        .iter()
        .filter(|r| r.enabled)
        .map(|r| {
            let spans = match r.id.as_str() {
                "rrn" if r.builtin => rrn.clone(),
                "phone" if r.builtin => phone.clone(),
                "card" if r.builtin => card.clone(),
                "account" if r.builtin => account.clone(),
                "passport" if r.builtin => passport.clone(),
                "driver" if r.builtin => driver.clone(),
                "email" if r.builtin => email.clone(),
                _ => match r.pattern.as_deref().map(Regex::new) {
                    Some(Ok(re)) => re.find_iter(text).map(|m| m.range()).collect(),
                    _ => vec![],
                },
            };
            (r.id.clone(), spans)
        })
        .collect()
}

pub fn scan_text(text: &str, rules: &[PiiRule]) -> Vec<PiiHit> {
    matches(text, rules)
        .into_iter()
        .filter_map(|(id, spans)| {
            let rule = rules.iter().find(|r| r.id == id)?;
            let count = spans.len() as u32;
            (count > 0 && count >= rule.threshold.max(1)).then(|| PiiHit { rule_id: id, name: rule.name.clone(), count })
        })
        .collect()
}

fn mask_one(id: &str, s: &str) -> String {
    let star = |c: char| if c.is_alphanumeric() { '*' } else { c };
    match id {
        "rrn" => {
            let keep = if s.contains('-') { 8 } else { 7 };
            s.chars().enumerate().map(|(i, c)| if i < keep { c } else { star(c) }).collect()
        }
        "email" => {
            let (local, domain) = s.split_once('@').unwrap_or((s, ""));
            let keep = local.chars().count().min(2);
            let l: String = local.chars().enumerate().map(|(i, c)| if i < keep { c } else { '*' }).collect();
            format!("{l}@{domain}")
        }
        _ => {
            let n = s.chars().count();
            let keep = n.div_ceil(3);
            s.chars().enumerate().map(|(i, c)| if i < keep { c } else { star(c) }).collect()
        }
    }
}

/// Masks every match of every enabled rule, regardless of threshold.
pub fn mask_text(text: &str, rules: &[PiiRule]) -> String {
    let mut spans: Vec<(Range<usize>, String)> = matches(text, rules)
        .into_iter()
        .flat_map(|(id, v)| v.into_iter().map(move |r| (r, id.clone())))
        .collect();
    spans.sort_by_key(|(r, _)| (r.start, std::cmp::Reverse(r.end)));
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for (r, id) in spans {
        if r.start < pos {
            continue;
        }
        out.push_str(&text[pos..r.start]);
        out.push_str(&mask_one(&id, &text[r.clone()]));
        pos = r.end;
    }
    out.push_str(&text[pos..]);
    out
}

pub fn validate_custom(pattern: &str) -> Result<(), String> {
    Regex::new(pattern).map(|_| ()).map_err(|e| format!("정규식 오류: {e}"))
}

/// Strongest action among hit rules, plus the unscannable action when the file could not be read.
pub fn decide(hits: &[PiiHit], unscannable: bool, rules: &[PiiRule], unscannable_action: PiiAction) -> Option<PiiAction> {
    let from_hits = hits.iter().filter_map(|h| rules.iter().find(|r| r.id == h.rule_id).map(|r| r.action));
    from_hits.chain(unscannable.then_some(unscannable_action)).max()
}
