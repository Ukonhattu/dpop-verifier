use url::{Url, Position};
use crate::DpopError;

/// Normalize scheme/host/port/path for DPoP htu compare:
/// - http/https only; lowercase scheme+host
/// - drop query & fragment
/// - elide default ports (80/443)
/// - ensure non-empty path ("/")
/// - resolve dot-segments
pub fn normalize_htu(input: &str) -> Result<String, DpopError> {
    let mut url = Url::parse(input).map_err(|_| DpopError::MalformedHtu)?;
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(DpopError::MalformedHtu);
    }
    if let Some(host) = url.host_str() {
        let _ = url.set_host(Some(&host.to_ascii_lowercase()));
    } else {
        return Err(DpopError::MalformedHtu);
    }
    url.set_fragment(None);
    url.set_query(None);

    let is_default = (scheme == "http" && url.port() == Some(80))
        || (scheme == "https" && url.port() == Some(443));
    if is_default {
        let _ = url.set_port(None);
    }
    if url.path().is_empty() {
        url.set_path("/");
    }
    // resolve dot-segments
    let mut norm: Vec<&str> = Vec::new();
    {
        let segs = url.path_segments().ok_or(DpopError::MalformedHtu)?;
        for s in segs {
            match s {
                "" | "." => {}
                ".." => { norm.pop(); }
                other => norm.push(other),
            }
        }
    }
    let mut new_path = String::from("/");
    new_path.push_str(&norm.join("/"));
    url.set_path(&new_path);

    Ok(url[..Position::AfterPath].to_string())
}


/// Normalize HTTP method for DPoP htm compare.
pub fn normalize_method(m: &str) -> Result<String, DpopError> {
    let up = m.trim().to_ascii_uppercase();
    // Restrict to standard methods (expand if you need more)
    if !matches!(up.as_str(), "GET"|"POST"|"PUT"|"PATCH"|"DELETE"|"HEAD"|"OPTIONS"|"TRACE") {
        return Err(DpopError::InvalidMethod);
    }
    Ok(up)
}

