use super::*;
use crate::network_manager::network::wasm::ws::ws_blocked_as_mixed_content;

// Mixed content is an https page's rule: from the runner's http://127.0.0.1 page, a secure
// context, plain ws:// reaches any peer, as main's WS-only bootstraps need
pub fn test_ws_allowed_from_a_secure_http_page() {
    assert!(
        is_secure_context() && !is_browser_https(),
        "the wasm test runner serves its page over http from loopback, a secure context"
    );
    assert!(!ws_blocked_as_mixed_content());
}
