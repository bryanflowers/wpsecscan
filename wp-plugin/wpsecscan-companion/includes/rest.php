<?php
/**
 * REST endpoint: /wp-json/wpsecscan/v1/diagnostics
 *
 * @package WPSecScan_Companion
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Register the route.
 */
function wpsecscan_companion_register_routes() {
    register_rest_route( 'wpsecscan/v1', '/diagnostics', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_diagnostics_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // FEAT-036: rolling SHA-256 manifest of plugin + theme files for the
    // external scanner's continuous file-change monitor.
    register_rest_route( 'wpsecscan/v1', '/file-monitor', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_file_monitor_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // FEAT-039: app-passwords policy — is the feature enabled, are
    // session expirations configured, is any IP-restriction plugin active?
    register_rest_route( 'wpsecscan/v1', '/app-passwords-policy', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_app_passwords_policy_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // FEAT-042: slow-query-log path — is `slow_query_log_file` inside
    // the web root, where a misconfigured nginx/Apache could serve it?
    register_rest_route( 'wpsecscan/v1', '/slow-query-log', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_slow_query_log_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
}

/**
 * Validate the X-WPSecScan-Token header against the stored hash.
 * Marks the token used on success. Enforces TLS, TTL, single-use.
 *
 * @return bool|WP_Error
 */
function wpsecscan_companion_check_token( $request ) {
    // Enforce TLS unless explicitly disabled (dev / local only).
    if ( ! is_ssl() && ! ( defined( 'WPSECSCAN_COMPANION_ALLOW_HTTP' ) && WPSECSCAN_COMPANION_ALLOW_HTTP ) ) {
        return new WP_Error( 'wpsecscan_no_tls', 'TLS required', [ 'status' => 403 ] );
    }

    // Header-only — query params can leak into server logs / proxy logs.
    $token = $request->get_header( 'x_wpsecscan_token' );
    $token = is_string( $token ) ? trim( $token ) : '';
    if ( ! $token || strlen( $token ) < 16 || strlen( $token ) > 96 ) {
        return new WP_Error( 'wpsecscan_bad_token', 'Bad token', [ 'status' => 401 ] );
    }

    $stored = get_option( WPSECSCAN_COMPANION_TOKEN_OPTION );
    if ( ! is_array( $stored ) || empty( $stored['token'] ) ) {
        return new WP_Error( 'wpsecscan_no_token', 'No active token', [ 'status' => 401 ] );
    }
    if ( ! empty( $stored['used'] ) ) {
        return new WP_Error( 'wpsecscan_used_token', 'Token already used', [ 'status' => 401 ] );
    }
    if ( ( time() - (int) ( $stored['created'] ?? 0 ) ) > WPSECSCAN_COMPANION_TOKEN_TTL ) {
        delete_option( WPSECSCAN_COMPANION_TOKEN_OPTION );
        return new WP_Error( 'wpsecscan_expired', 'Token expired', [ 'status' => 401 ] );
    }
    if ( ! wp_check_password( $token, $stored['token'] ) ) {
        return new WP_Error( 'wpsecscan_bad_token', 'Bad token', [ 'status' => 401 ] );
    }

    // Mark consumed.
    $stored['used'] = true;
    update_option( WPSECSCAN_COMPANION_TOKEN_OPTION, $stored, false );

    return true;
}

/**
 * FEAT-036 — return a rolling SHA-256 manifest of every file under the
 * active plugin + theme directories. The external scanner compares this
 * against the prior manifest and surfaces any diff as a critical finding
 * (most file changes outside upgrade windows are tampering).
 */
function wpsecscan_companion_file_monitor_callback( $request ) {
    $manifest = [];
    foreach ( [ WP_PLUGIN_DIR, get_theme_root() ] as $root ) {
        if ( ! is_dir( $root ) ) {
            continue;
        }
        $rii = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
        foreach ( $rii as $file ) {
            if ( ! $file->isFile() ) continue;
            $path = $file->getPathname();
            // Skip large binary files (uploads occasionally sit under plugin dirs)
            if ( $file->getSize() > 2 * 1024 * 1024 ) continue;
            $rel = ltrim( str_replace( ABSPATH, '', $path ), '/\\' );
            $manifest[ $rel ] = hash_file( 'sha256', $path );
        }
    }
    return rest_ensure_response( [
        'manifest'   => $manifest,
        'count'      => count( $manifest ),
        'generated'  => gmdate( 'c' ),
        'roots'      => [ 'plugins' => WP_PLUGIN_DIR, 'themes' => get_theme_root() ],
    ] );
}

/**
 * FEAT-039 — report the WordPress Application Passwords policy: is the
 * feature enabled, when do sessions expire, and is any known IP-restriction
 * plugin active to limit where an AP can be used from?
 */
function wpsecscan_companion_app_passwords_policy_callback( $request ) {
    $ap_enabled = apply_filters( 'wp_is_application_passwords_available', true );
    // Common IP-restriction / 2FA-on-AP plugins. Loose detection.
    $known_restrictors = [
        'wordfence/wordfence.php',
        'wordfence-login-security/wordfence-login-security.php',
        'better-wp-security/better-wp-security.php',         // iThemes / Solid
        'all-in-one-wp-security-and-firewall/wp-security.php',
        'sucuri-scanner/sucuri.php',
    ];
    $active = (array) get_option( 'active_plugins', [] );
    $restrictors_active = array_values( array_intersect( $known_restrictors, $active ) );
    return rest_ensure_response( [
        'app_passwords_enabled'    => (bool) $ap_enabled,
        'restrictor_plugins'       => $restrictors_active,
        'restrictor_count'         => count( $restrictors_active ),
        'auth_cookie_expiration'   => apply_filters( 'auth_cookie_expiration', 14 * DAY_IN_SECONDS, 0, false ),
        'recommendation'           => $ap_enabled && empty( $restrictors_active )
            ? 'Application Passwords are enabled but no IP-restriction plugin was detected — a leaked AP can be used from any global IP indefinitely.'
            : ( $ap_enabled ? 'Application Passwords enabled and an IP-restriction plugin is active.' : 'Application Passwords are disabled.' ),
    ] );
}

/**
 * FEAT-042 — report whether the MySQL slow-query-log file is configured
 * inside the document root (a common cheap-shared-hosting misconfig
 * that lets visitors download production query logs).
 */
function wpsecscan_companion_slow_query_log_callback( $request ) {
    global $wpdb;
    $row     = $wpdb->get_row( "SHOW VARIABLES LIKE 'slow_query_log_file'", ARRAY_A );
    $enabled = $wpdb->get_row( "SHOW VARIABLES LIKE 'slow_query_log'", ARRAY_A );
    $log_path = isset( $row['Value'] ) ? (string) $row['Value'] : '';
    $on      = isset( $enabled['Value'] ) && strtolower( (string) $enabled['Value'] ) === 'on';
    $abspath = realpath( ABSPATH ) ?: ABSPATH;
    $in_web_root = false;
    if ( $log_path ) {
        $real = realpath( $log_path );
        if ( $real && strpos( $real, $abspath ) === 0 ) {
            $in_web_root = true;
        }
    }
    return rest_ensure_response( [
        'slow_log_enabled'  => (bool) $on,
        'slow_log_file'     => $log_path,
        'inside_web_root'   => (bool) $in_web_root,
        'web_root'          => $abspath,
        'recommendation'    => $in_web_root
            ? 'Move slow_query_log_file OUTSIDE the web root immediately — a misconfigured web server could serve this file to visitors. Typical safe path: /var/log/mysql/slow.log (root-readable only).'
            : 'Slow-query-log is outside the web root (good).',
    ] );
}

/**
 * Diagnostics callback. Logs the access then returns the payload.
 */
function wpsecscan_companion_diagnostics_callback( $request ) {
    $payload = wpsecscan_companion_build_diagnostics();

    // Audit log (best-effort).
    $log   = (array) get_option( WPSECSCAN_COMPANION_LOG_OPTION, [] );
    $log[] = [
        'when'     => gmdate( 'c' ),
        'ip'       => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
        'result'   => 'OK (' . count( $payload['plugins'] ?? [] ) . ' plugins, ' . count( $payload['users'] ?? [] ) . ' users)',
        'sections' => implode( ',', array_keys( $payload ) ),
    ];
    // Keep last 50.
    if ( count( $log ) > 50 ) {
        $log = array_slice( $log, -50 );
    }
    update_option( WPSECSCAN_COMPANION_LOG_OPTION, $log, false );

    return rest_ensure_response( $payload );
}
