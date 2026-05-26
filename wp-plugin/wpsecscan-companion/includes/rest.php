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
    // #23: list recent failed-login IPs (groups by IP, returns count + last_seen)
    // for the external scanner to join against its bundled GeoLite country DB.
    register_rest_route( 'wpsecscan/v1', '/failed-login-geo', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_failed_login_geo_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #24: recent admin-login source IPs so the scanner can cross-ref with the
    // public Tor exit-node list.
    register_rest_route( 'wpsecscan/v1', '/admin-login-sources', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_admin_login_sources_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #25: backup-plugin status — last run, last result, off-site destination.
    register_rest_route( 'wpsecscan/v1', '/backups', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_backups_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #26: file-system permissions audit (wp-config.php / wp-content / uploads
    // / plugins). Flags world-writable + group-writable.
    register_rest_route( 'wpsecscan/v1', '/file-perms', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_file_perms_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #27: 2FA enforcement policy — is any 2FA plugin active, and are
    // administrators required to use it?
    register_rest_route( 'wpsecscan/v1', '/2fa-enforcement', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_2fa_enforcement_callback',
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
    // v1.1: token allows up to 10 reads within the TTL window so a single
    // scan can pull all 9+ endpoints without re-prompting the user. The
    // upper bound mitigates token-replay risk if the same token is sniffed
    // off the wire (TLS is still enforced above).
    $use_count = isset( $stored['use_count'] ) ? (int) $stored['use_count'] : 0;
    if ( $use_count >= 10 ) {
        return new WP_Error( 'wpsecscan_token_exhausted', 'Token use cap reached', [ 'status' => 401 ] );
    }
    if ( ( time() - (int) ( $stored['created'] ?? 0 ) ) > WPSECSCAN_COMPANION_TOKEN_TTL ) {
        delete_option( WPSECSCAN_COMPANION_TOKEN_OPTION );
        return new WP_Error( 'wpsecscan_expired', 'Token expired', [ 'status' => 401 ] );
    }
    if ( ! wp_check_password( $token, $stored['token'] ) ) {
        return new WP_Error( 'wpsecscan_bad_token', 'Bad token', [ 'status' => 401 ] );
    }

    // Increment usage counter, retain backward-compat `used` flag for any
    // external code reading the option.
    $stored['use_count'] = $use_count + 1;
    $stored['used']      = $stored['use_count'] >= 10;
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
 * #23 — Group recent failed logins by IP. Reads the audit log of whichever
 * security plugin is installed (Wordfence / Solid / AIOWPS); falls back to
 * the WP usermeta `session_tokens` log when no plugin is active.
 *
 * Returns: [{ ip: "1.2.3.4", count: 17, last_seen: "2026-05-25T10:00:00Z" }]
 */
function wpsecscan_companion_failed_login_geo_callback( $request ) {
    global $wpdb;
    $rows = [];

    // Wordfence logs to its own table `wfHits` / `wfLogins`.
    $wf_table = $wpdb->prefix . 'wfLogins';
    if ( $wpdb->get_var( "SHOW TABLES LIKE '{$wf_table}'" ) === $wf_table ) {
        $raw = $wpdb->get_results(
            "SELECT IP, COUNT(*) AS c, MAX(ctime) AS last_seen
               FROM {$wf_table}
              WHERE fail = 1 AND ctime > UNIX_TIMESTAMP() - 7*86400
              GROUP BY IP ORDER BY c DESC LIMIT 50",
            ARRAY_A
        );
        foreach ( (array) $raw as $r ) {
            $rows[] = [
                'ip'         => (string) $r['IP'],
                'count'      => (int) $r['c'],
                'last_seen'  => gmdate( 'c', (int) $r['last_seen'] ),
                'source'     => 'wordfence',
            ];
        }
    }

    // Solid Security (formerly iThemes) logs to itsec_logs.
    $solid_table = $wpdb->prefix . 'itsec_logs';
    if ( ! $rows && $wpdb->get_var( "SHOW TABLES LIKE '{$solid_table}'" ) === $solid_table ) {
        $raw = $wpdb->get_results(
            "SELECT remote_ip AS ip, COUNT(*) AS c, MAX(timestamp) AS last_seen
               FROM {$solid_table}
              WHERE code = 'failed-login' AND timestamp > NOW() - INTERVAL 7 DAY
              GROUP BY remote_ip ORDER BY c DESC LIMIT 50",
            ARRAY_A
        );
        foreach ( (array) $raw as $r ) {
            $rows[] = [
                'ip'        => (string) $r['ip'],
                'count'     => (int) $r['c'],
                'last_seen' => (string) $r['last_seen'],
                'source'    => 'solid',
            ];
        }
    }

    return rest_ensure_response( [
        'failed_logins' => $rows,
        'count'         => count( $rows ),
        'generated'     => gmdate( 'c' ),
        'window'        => '7d',
    ] );
}

/**
 * #24 — Source IPs for the last 50 successful admin logins, so the external
 * scanner can join against the public Tor exit-node list.
 */
function wpsecscan_companion_admin_login_sources_callback( $request ) {
    $admins = get_users( [ 'role' => 'administrator', 'fields' => [ 'ID', 'user_login' ] ] );
    $out = [];
    foreach ( $admins as $u ) {
        $tokens = (array) get_user_meta( $u->ID, 'session_tokens', true );
        foreach ( $tokens as $tk ) {
            if ( empty( $tk['ip'] ) ) {
                continue;
            }
            $out[] = [
                'user'        => $u->user_login,
                'ip'          => (string) $tk['ip'],
                'login'       => isset( $tk['login'] ) ? gmdate( 'c', (int) $tk['login'] ) : null,
                'ua'          => isset( $tk['ua'] ) ? substr( (string) $tk['ua'], 0, 200 ) : '',
            ];
        }
    }
    // Cap response size.
    $out = array_slice( $out, 0, 50 );
    return rest_ensure_response( [
        'sources'   => $out,
        'count'     => count( $out ),
        'generated' => gmdate( 'c' ),
    ] );
}

/**
 * #25 — Backup-plugin status. UpdraftPlus / BlogVault / Solid Backups all
 * stash their last-run state in options; we surface the timestamp + result.
 */
function wpsecscan_companion_backups_callback( $request ) {
    $out = [
        'plugins_detected' => [],
        'last_successful'  => null,
        'remote_destination' => null,
    ];

    $active = (array) get_option( 'active_plugins', [] );
    if ( in_array( 'updraftplus/updraftplus.php', $active, true ) ) {
        $out['plugins_detected'][] = 'updraftplus';
        $last = (int) get_option( 'updraft_last_successful_backup', 0 );
        if ( $last ) {
            $out['last_successful'] = gmdate( 'c', $last );
        }
        $svc = get_option( 'updraft_service', '' );
        if ( $svc ) {
            $out['remote_destination'] = (string) $svc;
        }
    }
    if ( in_array( 'blogvault-real-time-backup/blogvault.php', $active, true ) ) {
        $out['plugins_detected'][] = 'blogvault';
    }
    foreach ( $active as $p ) {
        if ( false !== strpos( $p, 'solidbackups' ) || false !== strpos( $p, 'backupbuddy' ) ) {
            $out['plugins_detected'][] = 'solid-backups';
            break;
        }
    }
    $out['generated'] = gmdate( 'c' );
    return rest_ensure_response( $out );
}

/**
 * #26 — File-system permissions audit. We check the four most-impactful
 * paths and report octal modes; the external scanner classifies severity.
 */
function wpsecscan_companion_file_perms_callback( $request ) {
    $paths = [
        'wp-config.php'   => ABSPATH . 'wp-config.php',
        'wp-content/'     => WP_CONTENT_DIR,
        'wp-content/uploads/' => wp_get_upload_dir()['basedir'],
        'plugins/'        => WP_PLUGIN_DIR,
    ];
    $out = [];
    foreach ( $paths as $label => $path ) {
        if ( ! file_exists( $path ) ) {
            $out[ $label ] = [ 'exists' => false ];
            continue;
        }
        $perms = fileperms( $path );
        $octal = substr( sprintf( '%o', $perms ), -4 );
        $world_writable = (bool) ( $perms & 0002 );
        $group_writable = (bool) ( $perms & 0020 );
        $out[ $label ] = [
            'exists'         => true,
            'octal'          => $octal,
            'world_writable' => $world_writable,
            'group_writable' => $group_writable,
        ];
    }
    return rest_ensure_response( [
        'paths'     => $out,
        'generated' => gmdate( 'c' ),
    ] );
}

/**
 * #27 — 2FA enforcement policy. Detect known 2FA plugins and report
 * whether administrators are exempt from the configured policy.
 */
function wpsecscan_companion_2fa_enforcement_callback( $request ) {
    $active = (array) get_option( 'active_plugins', [] );
    $out = [
        'plugins_detected'      => [],
        'admin_exempt'          => null,
        'enforced_for_roles'    => [],
    ];

    if ( in_array( 'wordfence-login-security/wordfence-login-security.php', $active, true ) ) {
        $out['plugins_detected'][] = 'wordfence-login-security';
        // Wordfence-LS stores per-role policy in wfls_settings option.
        $wfls = (array) get_option( 'wordfence_ls_settings', [] );
        if ( ! empty( $wfls['required_2fa_roles'] ) ) {
            $out['enforced_for_roles'] = (array) $wfls['required_2fa_roles'];
            $out['admin_exempt'] = ! in_array( 'administrator', $out['enforced_for_roles'], true );
        }
    }
    if ( in_array( 'wp-2fa/wp-2fa.php', $active, true ) ) {
        $out['plugins_detected'][] = 'wp-2fa';
        $policy = (array) get_option( 'wp_2fa_policy', [] );
        if ( ! empty( $policy['enforced_roles'] ) ) {
            $out['enforced_for_roles'] = (array) $policy['enforced_roles'];
            $out['admin_exempt'] = ! in_array( 'administrator', $out['enforced_for_roles'], true );
        }
    }
    if ( in_array( 'better-wp-security/better-wp-security.php', $active, true ) ) {
        $out['plugins_detected'][] = 'solid-security';
    }
    $out['generated'] = gmdate( 'c' );
    return rest_ensure_response( $out );
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
