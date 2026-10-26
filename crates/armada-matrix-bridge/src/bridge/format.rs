//! Text conversion. Armada messages are markdown with NIP-21 `nostr:` mentions;
//! Matrix messages carry a plain `body` and optional HTML with matrix.to pills.

use nostr::nips::nip19::{FromBech32, Nip19Profile, ToBech32};
use nostr::prelude::PublicKey;
use pulldown_cmark::{Event, Options, Parser, html};

/// A mention resolved for Matrix.
pub struct Pill {
    pub mxid: String,
    pub name: String,
}

/// Every pubkey mentioned as `nostr:npub1…` / `nostr:nprofile1…` in `content`, with
/// the byte range of the mention.
pub fn find_mentions(content: &str) -> Vec<(std::ops::Range<usize>, PublicKey)> {
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(i) = content[start..].find("nostr:") {
        let at = start + i;
        let rest = &content[at + 6..];
        let end = rest.find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(rest.len());
        let word = &rest[..end];
        let pk = if word.starts_with("npub1") {
            PublicKey::from_bech32(word).ok()
        } else if word.starts_with("nprofile1") {
            Nip19Profile::from_bech32(word).ok().map(|p| p.public_key)
        } else {
            None
        };
        if let Some(pk) = pk {
            out.push((at..at + 6 + end, pk));
        }
        start = at + 6 + end;
    }
    out
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Render Armada markdown for Matrix: `(body, Some(html))`, or `None` for HTML when
/// the message is plain text. `resolve` turns mentioned pubkeys into pills.
pub fn armada_to_matrix(content: &str, resolve: &dyn Fn(&PublicKey) -> Option<Pill>) -> (String, Option<String>, Vec<String>) {
    // Swap mentions for placeholders that markdown leaves alone.
    let mentions = find_mentions(content);
    let mut body = String::new();
    let mut md = String::new();
    let mut pills: Vec<(String, String)> = Vec::new();
    let mut mentioned = Vec::new();
    let mut last = 0;
    for (range, pk) in &mentions {
        body.push_str(&content[last..range.start]);
        md.push_str(&content[last..range.start]);
        match resolve(pk) {
            Some(pill) => {
                body.push_str(&pill.name);
                let token = format!("\u{E000}{}\u{E001}", pills.len());
                md.push_str(&token);
                mentioned.push(pill.mxid.clone());
                pills.push((pill.mxid, pill.name));
            }
            None => {
                let short = pk.to_bech32().map(|n| format!("{}…", &n[..12])).unwrap_or_default();
                body.push_str(&short);
                md.push_str(&short);
            }
        }
        last = range.end;
    }
    body.push_str(&content[last..]);
    md.push_str(&content[last..]);

    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TABLES);
    // Raw HTML in a message is text, never markup.
    let events = Parser::new_ext(&md, opts).map(|e| match e {
        Event::Html(s) | Event::InlineHtml(s) => Event::Text(s),
        e => e,
    });
    let mut out = String::new();
    html::push_html(&mut out, events);
    let mut out = out.trim_end().to_owned();
    if let Some(inner) = out.strip_prefix("<p>").and_then(|s| s.strip_suffix("</p>"))
        && !inner.contains("<p>")
    {
        out = inner.to_owned();
    }
    for (i, (mxid, name)) in pills.iter().enumerate() {
        out = out.replace(&format!("\u{E000}{i}\u{E001}"), &format!("<a href=\"https://matrix.to/#/{}\">{}</a>", escape_html(mxid), escape_html(name)));
    }
    let plain = escape_html(&body).replace('\n', "<br />");
    let html = (out != plain && out != escape_html(&body)).then_some(out);
    (body, html, mentioned)
}

/// Convert a Matrix message to Armada markdown. `resolve` maps an MXID (from a pill)
/// to the pubkey that should be mentioned; returns `(content, mentioned pubkeys)`.
pub fn matrix_to_armada(body: &str, html: Option<&str>, is_reply: bool, resolve: &dyn Fn(&str) -> Option<PublicKey>) -> (String, Vec<PublicKey>) {
    let mut mentioned = Vec::new();
    let text = match html {
        Some(html) => {
            let html = strip_mx_reply(html);
            let html = replace_pills(&html, resolve, &mut mentioned);
            htmd::convert(&html).unwrap_or_else(|_| body.to_owned())
        }
        None if is_reply => strip_reply_fallback(body),
        None => body.to_owned(),
    };
    (text.trim().to_owned(), mentioned)
}

/// A NIP-30 shortcode from a Matrix one (`:party_parrot:` or `party parrot`):
/// letters, digits, `_` and `-` only.
pub fn shortcode(s: &str) -> String {
    let code: String = s.trim().trim_matches(':').chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
    if code.trim_matches('_').is_empty() { "emoji".into() } else { code }
}

/// Matrix custom emoji (`<img data-mx-emoticon src="mxc://…" alt=":code:">`)
/// become `:code:` in the HTML; returns it and each (shortcode, mxc).
pub fn take_emoticons(html: &str) -> (String, Vec<(String, String)>) {
    let mut out = String::new();
    let mut found: Vec<(String, String)> = vec![];
    let mut rest = html;
    while let Some(i) = rest.find("<img") {
        out.push_str(&rest[..i]);
        let Some(end) = rest[i..].find('>') else {
            rest = &rest[i..];
            break;
        };
        let tag = &rest[i..i + end + 1];
        rest = &rest[i + end + 1..];
        let attr = |name: &str| {
            let at = tag.find(&format!(" {name}=\""))? + name.len() + 3;
            tag[at..].find('"').map(|len| tag[at..at + len].to_owned())
        };
        match (tag.contains("data-mx-emoticon"), attr("src").filter(|s| s.starts_with("mxc://"))) {
            (true, Some(src)) => {
                let code = shortcode(&attr("alt").or_else(|| attr("title")).unwrap_or_default());
                out.push_str(&format!(":{code}:"));
                if !found.iter().any(|(c, _)| *c == code) {
                    found.push((code, src));
                }
            }
            _ => out.push_str(tag),
        }
    }
    out.push_str(rest);
    (out, found)
}

fn strip_mx_reply(html: &str) -> String {
    match (html.find("<mx-reply>"), html.find("</mx-reply>")) {
        (Some(a), Some(b)) if b > a => format!("{}{}", &html[..a], &html[b + "</mx-reply>".len()..]),
        _ => html.to_owned(),
    }
}

/// Plain-text reply fallbacks are `> ` lines followed by a blank line.
pub fn strip_reply_fallback(body: &str) -> String {
    if !body.starts_with("> ") {
        return body.to_owned();
    }
    let mut lines = body.lines().peekable();
    while lines.peek().is_some_and(|l| l.starts_with('>')) {
        lines.next();
    }
    if lines.peek().is_some_and(|l| l.is_empty()) {
        lines.next();
    }
    lines.collect::<Vec<_>>().join("\n")
}

fn replace_pills(html: &str, resolve: &dyn Fn(&str) -> Option<PublicKey>, mentioned: &mut Vec<PublicKey>) -> String {
    const OPEN: &str = "<a href=\"https://matrix.to/#/";
    let mut out = String::new();
    let mut rest = html;
    while let Some(i) = rest.find(OPEN) {
        out.push_str(&rest[..i]);
        let after = &rest[i + OPEN.len()..];
        let (Some(q), Some(close)) = (after.find('"'), after.find("</a>")) else {
            out.push_str(&rest[i..]);
            return out;
        };
        let target = percent_encoding::percent_decode_str(&after[..q]).decode_utf8_lossy().to_string();
        let target = target.split(['?', '/']).next().unwrap_or("").to_owned();
        match target.starts_with('@').then(|| resolve(&target)).flatten() {
            Some(pk) => {
                out.push_str(&format!("nostr:{}", pk.to_bech32().unwrap_or_default()));
                mentioned.push(pk);
                rest = &after[close + 4..];
            }
            None => {
                out.push_str(OPEN);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NPUB: &str = "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m";

    #[test]
    fn emoticons_become_shortcodes() {
        let html = r#"hi <img data-mx-emoticon src="mxc://hs/abc" alt=":toad hype:" title=":toad hype:" height="32" /> and <img src="mxc://hs/pic" alt="pic">"#;
        let (out, found) = take_emoticons(html);
        assert_eq!(out, r#"hi :toad_hype: and <img src="mxc://hs/pic" alt="pic">"#);
        assert_eq!(found, vec![("toad_hype".to_owned(), "mxc://hs/abc".to_owned())]);
        assert_eq!(shortcode("dave"), "dave");
        assert_eq!(shortcode("::"), "emoji");
    }

    #[test]
    fn markdown_and_mentions_render() {
        let pk = PublicKey::from_bech32(NPUB).unwrap();
        let resolve = |p: &PublicKey| (*p == pk).then(|| Pill { mxid: "@armada_x:hs".into(), name: "Alice".into() });
        let (body, html, mentioned) = armada_to_matrix(&format!("hi nostr:{NPUB} **bold** <b>x</b>"), &resolve);
        assert_eq!(body, "hi Alice **bold** <b>x</b>");
        assert_eq!(html.unwrap(), "hi <a href=\"https://matrix.to/#/@armada_x:hs\">Alice</a> <strong>bold</strong> &lt;b&gt;x&lt;/b&gt;");
        assert_eq!(mentioned, ["@armada_x:hs"]);
        let (_, html, _) = armada_to_matrix("just text", &resolve);
        assert!(html.is_none());
    }

    #[test]
    fn matrix_pills_become_mentions() {
        let pk = PublicKey::from_bech32(NPUB).unwrap();
        let resolve = |m: &str| (m == "@bob:hs").then_some(pk);
        let html = "<mx-reply><blockquote>old</blockquote></mx-reply>hey <a href=\"https://matrix.to/#/@bob:hs\">Bob</a> <em>yes</em>";
        let (text, mentioned) = matrix_to_armada("> old\n\nhey Bob yes", Some(html), true, &resolve);
        assert_eq!(text, format!("hey nostr:{NPUB} *yes*"));
        assert_eq!(mentioned, [pk]);
        assert_eq!(strip_reply_fallback("> <@a:b> old\n> more\n\nnew"), "new");
    }
}
