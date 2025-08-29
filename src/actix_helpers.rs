#[cfg(feature = "actix-web")]
use actix_web::HttpRequest;

#[cfg(feature = "actix-web")]
use crate::DpopError;

#[cfg(feature = "actix-web")]
/// Return the single DPoP header as &str; error if missing or multiple.
pub fn dpop_header_str<'a>(req: &'a HttpRequest) -> Result<&'a str, DpopError> {
    let mut it = req.headers().get_all("DPoP");
    let first = it.next().ok_or(DpopError::MalformedJws)?;
    if it.next().is_some() {
        return Err(DpopError::MalformedJws);
    }
    first.to_str().map_err(|_| DpopError::MalformedJws)
}

#[cfg(feature = "actix-web")]
/// Build canonical HTU (no query/fragment), honoring common proxy headers.
/// - lowercases scheme/host
/// - prefers X-Forwarded-* when present
/// - drops default ports (:80 on http, :443 on https)
pub fn canonicalize_request_url(req: &HttpRequest) -> String {
    // scheme
    let scheme = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| req.connection_info().scheme().to_ascii_lowercase());

    // host (prefer first value of X-Forwarded-Host)
    let xf_host = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());

    let host = xf_host.unwrap_or_else(|| req.connection_info().host().to_string());

    // optional explicit forwarded port
    let mut port_opt = req
        .headers()
        .get("x-forwarded-port")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u16>().ok());

    // split host[:port] (careful with IPv6 “[::1]”)
    let (mut host_only, mut host_port_opt) = {
        let s = host.trim();
        if let Some(close) = s.rfind(']') {
            if s.starts_with('[') && close > 0 {
                let h = &s[..=close];
                let rest = &s[close + 1..];
                let p = rest.strip_prefix(':').and_then(|t| t.parse::<u16>().ok());
                (h.to_string(), p)
            } else {
                (s.to_string(), None)
            }
        } else if let Some((h, p)) = s.rsplit_once(':') {
            if let Ok(pn) = p.parse::<u16>() {
                (h.to_string(), Some(pn))
            } else {
                (s.to_string(), None)
            }
        } else {
            (s.to_string(), None)
        }
    };

    if port_opt.is_none() {
        port_opt = host_port_opt.take();
    }

    host_only = host_only.to_ascii_lowercase();

    // drop default port
    if let Some(p) = port_opt {
        let is_default = (scheme == "http" && p == 80) || (scheme == "https" && p == 443);
        if is_default {
            port_opt = None;
        }
    }

    // path only (no query/fragment)
    let mut path = req.uri().path();
    if path.is_empty() {
        path = "/";
    }

    match port_opt {
        Some(p) => format!("{scheme}://{host_only}:{p}{path}"),
        None => format!("{scheme}://{host_only}{path}"),
    }
}
