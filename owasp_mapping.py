OWASP_STANDARDIZATION = {
    # M1
    "rules.hardcoded-api-key": "M1",
    "rules.plist-hardcoded-secret": "M1",
    "ios_hardcoded_info": "M1",

    # M2
    "cve_dependency_vulnerability": "M2",

    # M3
    "rules.insecure-biometrics": "M3",
    "rules.jwt-unverified-signature": "M3",
    "rules.insecure-keychain-accessibility": "M3",
    "rules.insecure-biometry-acl": "M3",
    "rules.insecure-device-identifier": "M3",
    "ios_biometric_bool": "M3",
    "ios_keychain_weak_accessibility_value": "M3",
    "ios_biometric_acl": "M3",

    # M4
    "rules.insecure-webview-evaluation": "M4",
    "rules.sql-injection-swift": "M4",
    "rules.tainted-sql-injection": "M4",
    "rules.tainted-webview-evaluation": "M4",
    "rules.tainted-path-traversal": "M4",
    "ios_webview_disable_js": "M4",

    # M5
    "no_http_urls": "M5",
    "rules.insecure-ats-configuration": "M5",
    "rules.insecure-ssl-validation-bypass": "M5",

    # M6
    "rules.insecure-local-authorization-role": "M6",

    # M7
    "force_unwrapping": "M7",

    # M9
    "no_print_statements": "M9",
    "no_user_defaults": "M9",
    "rules.insecure-local-storage": "M9",
    "rules.insecure-userdefaults": "M9",
    "rules.insecure-pasteboard": "M9",
    "rules.insecure-app-group": "M9",
    "ios_uipaste_sec": "M9",

    # M10
    "rules.insecure-md5-hashing": "M10",
    "rules.weak-rng": "M10",
    "rules.hardcoded-iv": "M10",
    "ios_swift_md5_collision": "M10",
    "ios_insecure_random_no_generator": "M10",

    # Linter Defaults
    "colon": "M5/M9",
    "duplicate_imports": "M5/M9",
    "redundant_discardable_let": "M5/M9",
    "line_length": "M5/M9",
    "unused_closure_parameter": "M5/M9"
}