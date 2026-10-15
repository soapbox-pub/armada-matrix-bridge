/// Normalize a relay URL so it can be used as a map key.
///
/// Lowercases the scheme and host, strips trailing slashes, and rejects
/// anything that is not a `ws://` or `wss://` URL with a non-empty host.
pub fn normalize_relay_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.chars().any(char::is_whitespace) {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "ws" && scheme != "wss" {
        return None;
    }
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (host, tail) = rest.split_at(host_end);
    if host.is_empty() || host.contains('@') {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix(':').unwrap_or(&host);
    if host.is_empty() || host.starts_with(':') {
        return None;
    }
    let tail = match tail.find(['?', '#']) {
        Some(i) => {
            let (path, query) = tail.split_at(i);
            format!("{}{}", path.trim_end_matches('/'), query)
        }
        None => tail.trim_end_matches('/').to_string(),
    };
    Some(format!("{scheme}://{host}{tail}"))
}

#[cfg(test)]
mod tests {
    use super::normalize_relay_url as n;

    #[test]
    fn normalizes() {
        assert_eq!(
            n("wss://Relay.Example.COM/").as_deref(),
            Some("wss://relay.example.com")
        );
        assert_eq!(
            n("WS://127.0.0.1:7777").as_deref(),
            Some("ws://127.0.0.1:7777")
        );
        assert_eq!(
            n("wss://r.example/Path/").as_deref(),
            Some("wss://r.example/Path")
        );
        assert_eq!(n("wss://r.example//").as_deref(), Some("wss://r.example"));
        assert_eq!(n(" wss://r.example ").as_deref(), Some("wss://r.example"));
        assert_eq!(
            n("wss://r.example/?a=1").as_deref(),
            Some("wss://r.example?a=1")
        );
    }

    #[test]
    fn rejects() {
        assert_eq!(n("https://relay.example.com"), None);
        assert_eq!(n("relay.example.com"), None);
        assert_eq!(n("wss://"), None);
        assert_eq!(n("wss:///path"), None);
        assert_eq!(n("wss://user@host"), None);
        assert_eq!(n("wss://a b"), None);
    }
}
