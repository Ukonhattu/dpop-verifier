#[cfg(feature = "actix-web")]
pub fn canonicalize_request_url(req: &actix_web::HttpRequest) -> String {
    let ci = req.connection_info();
    let mut scheme = ci.scheme().to_ascii_lowercase();
    let mut host = ci.host().to_string();

    // drop default ports
    if let Some((h, port)) = host.rsplit_once(':') {
        let default = (scheme == "http" && port == "80") || (scheme == "https" && port == "443");
        if default {
            host = h.to_string();
        }
    }
    let path = req.uri().path(); // ignore query/fragment per equal_htu
    format!("{scheme}://{host}{path}")
}
