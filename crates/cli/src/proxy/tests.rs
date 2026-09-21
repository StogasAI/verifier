use super::*;

fn config(browser: Option<&str>) -> ServeConfig {
    ServeConfig::new(&TransportOptions::default(), "127.0.0.1:1234", browser).unwrap()
}
fn request(config: &ServeConfig, path: &str) -> Request {
    Request::post(path)
        .header(header::HOST, &config.expected_host)
        .body(Body::empty())
        .unwrap()
}

#[test]
fn loopback_capability_host_origin_and_route_checks_run_before_any_network_io() {
    let config = config(Some("https://client.example"));
    let path = format!("/{}/v1/chat/completions", config.capability());
    let valid = request(&config, &path);
    assert!(
        matches!(route(&config, &valid).unwrap(), Route::Inference(value) if value == "/v1/chat/completions")
    );
    for path in [
        "/v1/chat/completions".to_owned(),
        format!("/{}/v1/files", config.capability()),
        format!("{path}?key=secret"),
        format!("/{}/v1/../chat/completions", config.capability()),
    ] {
        let error = route(&config, &request(&config, &path)).unwrap_err();
        assert_eq!(error.submission, "not_sent");
    }
    for host in [None, Some("localhost:1234"), Some("attacker.example")] {
        let mut request = request(&config, &path);
        request.headers_mut().remove(header::HOST);
        if let Some(host) = host {
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_str(host).unwrap());
        }
        assert_eq!(route(&config, &request).unwrap_err().reason, "invalid_host");
    }
    let mut duplicate = request(&config, &path);
    duplicate
        .headers_mut()
        .append(header::HOST, HeaderValue::from_static("127.0.0.1:1234"));
    assert_eq!(
        route(&config, &duplicate).unwrap_err().reason,
        "invalid_host"
    );
    for origin in ["null", "https://evil.example", "http://client.example"] {
        let mut request = request(&config, &path);
        request
            .headers_mut()
            .insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        assert_eq!(
            route(&config, &request).unwrap_err().reason,
            "invalid_origin"
        );
    }
    let mut browser = request(&config, &path);
    browser.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    assert!(matches!(
        route(&config, &browser).unwrap(),
        Route::Inference(_)
    ));
    browser.headers_mut().append(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    assert_eq!(
        route(&config, &browser).unwrap_err().reason,
        "invalid_origin"
    );
    let refresh = request(&config, &config.refresh_path());
    assert!(matches!(route(&config, &refresh).unwrap(), Route::Refresh));
    let mut refresh = refresh;
    refresh.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    assert_eq!(
        route(&config, &refresh).unwrap_err().reason,
        "invalid_refresh"
    );
}

#[test]
fn configuration_and_browser_preflight_cannot_expand_the_transport_scope() {
    for origin in [
        "http://public.example",
        "https://user:password@api.example",
        "https://api.example/v1",
        "https://api.example?x=y",
        "https://api.example#fragment",
    ] {
        let options = TransportOptions {
            base_url: Some(origin.into()),
            ..TransportOptions::default()
        };
        assert!(ServeConfig::new(&options, "127.0.0.1:1234", None).is_err());
    }
    assert!(ServeConfig::new(&TransportOptions::default(), "0.0.0.0:1234", None).is_err());
    assert!(ServeConfig::new(&TransportOptions::default(), "[::]:1234", None).is_err());
    assert!(ServeConfig::new(&TransportOptions::default(), "[::1]:1234", None).is_ok());
    let mut options = TransportOptions::default();
    assert_eq!(
        ServeConfig::new(&options, "127.0.0.1:1234", None)
            .unwrap()
            .upstream
            .as_str(),
        "https://api.stogas.ai/"
    );
    options.security = SecurityMode::E2ee;
    assert_eq!(
        ServeConfig::new(&options, "127.0.0.1:1234", None)
            .unwrap()
            .upstream
            .as_str(),
        "https://e2ee.stogas.ai/"
    );
    let config = config(Some("https://client.example"));
    let mut preflight = request(&config, &format!("/{}/v1/responses", config.capability()));
    *preflight.method_mut() = Method::OPTIONS;
    preflight.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        HeaderValue::from_static("POST"),
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_HEADERS,
        HeaderValue::from_static("authorization, stogas-metadata, content-type"),
    );
    assert!(matches!(
        route(&config, &preflight).unwrap(),
        Route::Preflight
    ));
    let response = browser_preflight(&preflight).unwrap();
    assert_eq!(response.status(), 204);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "POST, OPTIONS"
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        HeaderValue::from_static("GET"),
    );
    assert!(browser_preflight(&preflight).is_err());
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        HeaderValue::from_static("POST"),
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_HEADERS,
        HeaderValue::from_static("cookie"),
    );
    assert!(browser_preflight(&preflight).is_err());
}

#[test]
fn typed_failures_keep_revocation_separate_from_delivery_and_execution_uncertainty() {
    let revoked = Failure::native(&native_http::Error::Evidence(
        crate::evidence_client::Error::Verification(stogas_verifier::evidence::Error::Revoked),
    ));
    assert_eq!(
        (revoked.reason, revoked.submission),
        ("revoked", "not_sent")
    );
    let stale = Failure::evidence(&crate::evidence_client::Error::Verification(
        stogas_verifier::evidence::Error::CollateralExpired,
    ));
    assert_eq!(stale.reason, "expired_collateral");
    let absent = Failure::evidence(&crate::evidence_client::Error::Http(
        StatusCode::SERVICE_UNAVAILABLE,
    ));
    assert_eq!(absent.reason, "evidence_unavailable");
    let setup = Failure::native(&native_http::Error::Pool(http2_pool::Error::Connect(
        Box::new(crate::native_tls::Error::Profile),
    )));
    assert_eq!(
        (setup.reason, setup.submission),
        ("unsupported_profile", "not_sent")
    );
    let timeout = Failure::native(&native_http::Error::Pool(
        http2_pool::Error::ResponseDeadline,
    ));
    assert_eq!(timeout.submission, "execution_unknown");
    let response = Failure::encrypted(&encrypted_client::Error::Http(
        encrypted_http::Error::Response,
    ));
    assert_eq!(response.submission, "execution_unknown");
    let invalid = Failure::encrypted(&encrypted_client::Error::Http(
        encrypted_http::Error::Request,
    ));
    assert_eq!(
        (invalid.reason, invalid.submission),
        ("invalid_request", "not_sent")
    );
}
