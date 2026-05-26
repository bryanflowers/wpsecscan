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
    // ===== v1.2.0 endpoints =====
    // #11: list every currently-logged-in admin (from usermeta.session_tokens).
    register_rest_route( 'wpsecscan/v1', '/active-sessions', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_active_sessions_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #12: last N option changes + plugin (de)activations, sourced from
    // option_name LIKE pattern and active_plugins history.
    register_rest_route( 'wpsecscan/v1', '/recent-admin-actions', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_recent_admin_actions_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #17: per-table DB size from INFORMATION_SCHEMA.
    register_rest_route( 'wpsecscan/v1', '/db-size-by-table', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_db_size_by_table_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #18: recursive walk for .log / error_log / .htaccess.bak under web root.
    register_rest_route( 'wpsecscan/v1', '/log-files', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_log_files_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #19: last 50 lines of error_log with PII stripped.
    register_rest_route( 'wpsecscan/v1', '/php-error-log-tail', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_php_error_log_tail_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #13: hooks in _get_cron_array() with a failure count > 0.
    register_rest_route( 'wpsecscan/v1', '/wp-cron-failures', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_wp_cron_failures_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #14: cron hooks added in last 7 days, sorted by next-run time.
    register_rest_route( 'wpsecscan/v1', '/scheduled-task-anomalies', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_scheduled_task_anomalies_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #20: cron callbacks that reference shell-exec functions.
    register_rest_route( 'wpsecscan/v1', '/cron-shell-commands', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_cron_shell_commands_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #15: Redis/Memcached drop-in status.
    register_rest_route( 'wpsecscan/v1', '/object-cache-info', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_object_cache_info_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #16: total bytes of _transient_* rows.
    register_rest_route( 'wpsecscan/v1', '/transient-cache-size', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_transient_cache_size_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #21: wp_mail() deliverability indicators.
    register_rest_route( 'wpsecscan/v1', '/wp-mail-deliverability', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_wp_mail_deliverability_callback',
        'permission_callback' => 'wpsecscan_companion_check_token',
    ] );
    // #22: per-blog admin counts on a multisite network.
    register_rest_route( 'wpsecscan/v1', '/multisite-network-info', [
        'methods'             => 'GET',
        'callback'            => 'wpsecscan_companion_multisite_network_info_callback',
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

// ====================================================================
// v1.2.0 endpoint callbacks
// ====================================================================

/**
 * #11 — Currently-logged-in admins. Walks user_meta for `session_tokens`
 * on every administrator-role user and returns the active sessions.
 */
function wpsecscan_companion_active_sessions_callback( $request ) {
    $out = [];
    $admins = get_users( [
        'role'   => 'administrator',
        'fields' => [ 'ID', 'user_login', 'user_email' ],
    ] );
    foreach ( $admins as $u ) {
        $tokens = (array) get_user_meta( $u->ID, 'session_tokens', true );
        foreach ( $tokens as $hash => $tk ) {
            if ( ! is_array( $tk ) ) {
                continue;
            }
            $out[] = [
                'user_login'   => $u->user_login,
                'user_id'      => (int) $u->ID,
                'ip'           => isset( $tk['ip'] )         ? (string) $tk['ip']         : '',
                'login'        => isset( $tk['login'] )      ? gmdate( 'c', (int) $tk['login'] )      : null,
                'last_login'   => isset( $tk['last_login'] ) ? gmdate( 'c', (int) $tk['last_login'] ) : null,
                'expiration'   => isset( $tk['expiration'] ) ? gmdate( 'c', (int) $tk['expiration'] ) : null,
                'ua'           => isset( $tk['ua'] )         ? substr( (string) $tk['ua'], 0, 200 )   : '',
            ];
        }
    }
    return rest_ensure_response( [
        'active_sessions' => $out,
        'count'           => count( $out ),
        'generated'       => gmdate( 'c' ),
    ] );
}

/**
 * #12 — Last 50 option changes + plugin (de)activations.
 *
 * Note: WordPress doesn't keep a full audit log of option writes; this
 * relies on Wordfence's wfHits / Solid's itsec_logs / wp_audit_log when
 * present, falling back to a heuristic that scans recent options with
 * `_transient_*` (timestamped) and pulls the most-recent.
 */
function wpsecscan_companion_recent_admin_actions_callback( $request ) {
    global $wpdb;
    $rows = [];

    // Solid Security keeps a per-action audit table (itsec_logs).
    $solid = $wpdb->prefix . 'itsec_logs';
    if ( $wpdb->get_var( "SHOW TABLES LIKE '{$solid}'" ) === $solid ) {
        $raw = $wpdb->get_results(
            "SELECT timestamp, code, init_user_login AS user, data
               FROM {$solid}
              WHERE code IN ('plugin-activate','plugin-deactivate','plugin-install',
                             'theme-activate','option-update','user-create',
                             'user-role-changed')
              ORDER BY timestamp DESC LIMIT 50",
            ARRAY_A
        );
        foreach ( (array) $raw as $r ) {
            $rows[] = [
                'when'    => (string) $r['timestamp'],
                'code'    => (string) $r['code'],
                'user'    => (string) $r['user'],
                'source'  => 'solid',
            ];
        }
    }

    // Heuristic fallback: pull recently-updated transients to spot active
    // administrative activity (plugin updates write _site_transient_update_*).
    if ( ! $rows ) {
        $raw = $wpdb->get_results(
            "SELECT option_name FROM {$wpdb->options}
              WHERE option_name LIKE '\\_site\\_transient\\_update\\_%'
              ORDER BY option_id DESC LIMIT 20",
            ARRAY_A
        );
        foreach ( (array) $raw as $r ) {
            $rows[] = [
                'when'   => null,
                'code'   => 'transient-update',
                'option' => (string) $r['option_name'],
                'source' => 'heuristic',
            ];
        }
    }

    return rest_ensure_response( [
        'actions'   => $rows,
        'count'     => count( $rows ),
        'generated' => gmdate( 'c' ),
    ] );
}

/**
 * #17 — DB size per table via INFORMATION_SCHEMA.
 */
function wpsecscan_companion_db_size_by_table_callback( $request ) {
    global $wpdb;
    $raw = $wpdb->get_results( $wpdb->prepare(
        "SELECT table_name AS name,
                table_rows AS rows_estimate,
                data_length + index_length AS bytes
           FROM information_schema.tables
          WHERE table_schema = %s
          ORDER BY bytes DESC",
        DB_NAME
    ), ARRAY_A );
    $rows = [];
    foreach ( (array) $raw as $r ) {
        $rows[] = [
            'table' => (string) $r['name'],
            'rows'  => (int) $r['rows_estimate'],
            'bytes' => (int) $r['bytes'],
        ];
    }
    return rest_ensure_response( [
        'tables'    => $rows,
        'generated' => gmdate( 'c' ),
    ] );
}

/**
 * #18 — Log files exposed under the web root. Walks ABSPATH at depth ≤2
 * (deeper traversal is the file-monitor's job) and reports any *.log,
 * error_log, or .htaccess.bak.
 */
function wpsecscan_companion_log_files_callback( $request ) {
    $patterns = [ '*.log', 'error_log', 'debug.log', '.htaccess.bak', '.htaccess.old' ];
    $abspath  = realpath( ABSPATH ) ?: ABSPATH;
    $found    = [];
    // Top-level only — manifest-class deep walks live in /file-monitor.
    foreach ( $patterns as $pat ) {
        $matches = glob( $abspath . DIRECTORY_SEPARATOR . $pat );
        if ( $matches ) {
            foreach ( $matches as $m ) {
                $found[] = [
                    'path'  => ltrim( str_replace( $abspath, '', $m ), DIRECTORY_SEPARATOR ),
                    'bytes' => (int) @filesize( $m ),
                ];
            }
        }
    }
    // Also check immediate subdirectories one level deep.
    $subdirs = @scandir( $abspath ) ?: [];
    foreach ( $subdirs as $sd ) {
        if ( $sd[0] === '.' ) { continue; }
        $full = $abspath . DIRECTORY_SEPARATOR . $sd;
        if ( ! is_dir( $full ) ) { continue; }
        foreach ( $patterns as $pat ) {
            $matches = glob( $full . DIRECTORY_SEPARATOR . $pat );
            if ( $matches ) {
                foreach ( $matches as $m ) {
                    $found[] = [
                        'path'  => ltrim( str_replace( $abspath, '', $m ), DIRECTORY_SEPARATOR ),
                        'bytes' => (int) @filesize( $m ),
                    ];
                }
            }
        }
    }
    return rest_ensure_response( [
        'log_files' => $found,
        'count'     => count( $found ),
        'web_root'  => $abspath,
        'generated' => gmdate( 'c' ),
    ] );
}

/**
 * #15 — Object cache drop-in detection + status.
 */
function wpsecscan_companion_object_cache_info_callback( $request ) {
    $dropin    = WP_CONTENT_DIR . '/object-cache.php';
    $installed = file_exists( $dropin );
    $vendor    = '';
    if ( $installed ) {
        $body = (string) @file_get_contents( $dropin, false, null, 0, 2048 );
        if ( stripos( $body, 'Redis_Object_Cache' )    !== false ) { $vendor = 'redis-object-cache'; }
        elseif ( stripos( $body, 'W3_Object_Cache' )    !== false ) { $vendor = 'w3-total-cache'; }
        elseif ( stripos( $body, 'litespeed' )          !== false ) { $vendor = 'litespeed'; }
        elseif ( stripos( $body, 'memcached' )          !== false ) { $vendor = 'memcached'; }
        elseif ( stripos( $body, 'WP_Object_Cache' )    !== false ) { $vendor = 'unknown'; }
    }

    // Backend stats: try Redis via the Redis Object Cache plugin's globals.
    $stats = [];
    if ( function_exists( 'wp_object_cache_get_stats' ) ) {
        $s = @wp_object_cache_get_stats();
        if ( is_array( $s ) ) { $stats = $s; }
    }

    return rest_ensure_response( [
        'dropin_installed' => $installed,
        'dropin_vendor'    => $vendor,
        'dropin_path'      => $installed ? str_replace( ABSPATH, '', $dropin ) : '',
        'stats'            => $stats,
        'wp_using_ext_obj' => function_exists( 'wp_using_ext_object_cache' ) ? (bool) wp_using_ext_object_cache() : false,
        'generated'        => gmdate( 'c' ),
    ] );
}

/**
 * #16 — Bytes occupied by `_transient_*` rows in wp_options.
 */
function wpsecscan_companion_transient_cache_size_callback( $request ) {
    global $wpdb;
    $bytes_total = (int) $wpdb->get_var(
        "SELECT COALESCE( SUM( LENGTH( option_value ) ), 0 )
           FROM {$wpdb->options}
          WHERE option_name LIKE '\\_transient\\_%'
             OR option_name LIKE '\\_site\\_transient\\_%'"
    );
    $count = (int) $wpdb->get_var(
        "SELECT COUNT(*) FROM {$wpdb->options}
          WHERE option_name LIKE '\\_transient\\_%'
             OR option_name LIKE '\\_site\\_transient\\_%'"
    );
    // Spot the 5 fattest transient names so we surface what's bloating.
    $fattest = $wpdb->get_results(
        "SELECT option_name AS name, LENGTH( option_value ) AS bytes
           FROM {$wpdb->options}
          WHERE option_name LIKE '\\_transient\\_%'
             OR option_name LIKE '\\_site\\_transient\\_%'
          ORDER BY bytes DESC LIMIT 5",
        ARRAY_A
    );
    return rest_ensure_response( [
        'bytes_total' => $bytes_total,
        'count'       => $count,
        'fattest'     => array_map( function ( $r ) {
            return [ 'name' => (string) $r['name'], 'bytes' => (int) $r['bytes'] ];
        }, (array) $fattest ),
        'generated'   => gmdate( 'c' ),
    ] );
}

/**
 * #21 — Best-effort wp_mail() deliverability indicators. Reads any SMTP
 * plugin's stored last-send + last-error options when present.
 */
function wpsecscan_companion_wp_mail_deliverability_callback( $request ) {
    $out = [
        'plugins_detected' => [],
        'last_success_ts'  => null,
        'last_failure_ts'  => null,
        'last_failure'     => '',
    ];
    $active = (array) get_option( 'active_plugins', [] );
    // WP Mail SMTP by WPForms — stores transient `wp_mail_smtp_debug_event`.
    if ( in_array( 'wp-mail-smtp/wp_mail_smtp.php', $active, true ) ) {
        $out['plugins_detected'][] = 'wp-mail-smtp';
        $dbg = get_option( 'wp_mail_smtp_debug_event_last_error', '' );
        if ( $dbg ) {
            $out['last_failure']    = (string) $dbg;
        }
    }
    if ( in_array( 'fluent-smtp/fluent-smtp.php', $active, true ) ) {
        $out['plugins_detected'][] = 'fluent-smtp';
    }
    if ( in_array( 'easy-wp-smtp/easy-wp-smtp.php', $active, true ) ) {
        $out['plugins_detected'][] = 'easy-wp-smtp';
    }
    // Mailgun for WP.
    if ( in_array( 'mailgun/mailgun.php', $active, true ) ) {
        $out['plugins_detected'][] = 'mailgun';
    }
    $out['generated'] = gmdate( 'c' );
    return rest_ensure_response( $out );
}

/**
 * #22 — Multisite network info. Returns per-blog admin count + super-admin
 * list. Skipped (with explicit flag) on single-site installs so the
 * scanner can short-circuit cleanly.
 */
function wpsecscan_companion_multisite_network_info_callback( $request ) {
    if ( ! is_multisite() ) {
        return rest_ensure_response( [
            'is_multisite' => false,
            'generated'    => gmdate( 'c' ),
        ] );
    }
    $super = (array) get_super_admins();
    $blogs = function_exists( 'get_sites' ) ? get_sites( [ 'number' => 200 ] ) : [];
    $rows  = [];
    foreach ( $blogs as $b ) {
        switch_to_blog( (int) $b->blog_id );
        $admins = count_users()['avail_roles']['administrator'] ?? 0;
        restore_current_blog();
        $rows[] = [
            'blog_id'    => (int) $b->blog_id,
            'domain'     => (string) $b->domain,
            'path'       => (string) $b->path,
            'admin_count'=> (int) $admins,
            'registered' => (string) $b->registered,
        ];
    }
    return rest_ensure_response( [
        'is_multisite'   => true,
        'super_admins'   => $super,
        'super_count'    => count( $super ),
        'blogs'          => $rows,
        'blog_count'     => count( $rows ),
        'generated'      => gmdate( 'c' ),
    ] );
}

/**
 * #13 — Hooks in `_get_cron_array()` with failure count > 0.
 *
 * WordPress core doesn't track failure counts; we surface anything the
 * Action Scheduler library tracks (used by WooCommerce + many others) and
 * supplement with hooks that were due in the past but haven't run.
 */
function wpsecscan_companion_wp_cron_failures_callback( $request ) {
    $rows = [];
    // Action Scheduler — installed alongside WooCommerce and many plugins.
    global $wpdb;
    $as_table = $wpdb->prefix . 'actionscheduler_actions';
    if ( $wpdb->get_var( "SHOW TABLES LIKE '{$as_table}'" ) === $as_table ) {
        $raw = $wpdb->get_results(
            "SELECT hook, status, attempts, scheduled_date_gmt
               FROM {$as_table}
              WHERE status = 'failed' OR attempts > 3
              ORDER BY scheduled_date_gmt DESC LIMIT 50",
            ARRAY_A
        );
        foreach ( (array) $raw as $r ) {
            $rows[] = [
                'hook'      => (string) $r['hook'],
                'status'    => (string) $r['status'],
                'attempts'  => (int) $r['attempts'],
                'scheduled' => (string) $r['scheduled_date_gmt'],
                'source'    => 'action-scheduler',
            ];
        }
    }
    // Heuristic for vanilla wp-cron: hooks whose `next_run` is in the past.
    $cron = (array) _get_cron_array();
    $now  = time();
    $stuck = 0;
    foreach ( $cron as $ts => $hooks ) {
        if ( $ts >= $now ) { continue; }
        $diff = $now - (int) $ts;
        if ( $diff < 3600 ) { continue; } // < 1h late is normal
        foreach ( (array) $hooks as $hook_name => $args ) {
            $rows[] = [
                'hook'      => (string) $hook_name,
                'status'    => 'overdue',
                'overdue_s' => (int) $diff,
                'scheduled' => gmdate( 'c', (int) $ts ),
                'source'    => 'wp-cron',
            ];
            $stuck++;
            if ( $stuck >= 50 ) { break 2; }
        }
    }
    return rest_ensure_response( [
        'failures'  => $rows,
        'count'     => count( $rows ),
        'generated' => gmdate( 'c' ),
    ] );
}

/**
 * #14 — Cron hooks added in the last 7 days. WordPress doesn't keep
 * an explicit add-timestamp; we approximate using the `scheduled_date_gmt`
 * from Action Scheduler when available, else flag any hook whose next-run
 * is in the next 7 days (newly-scheduled often look like this).
 */
function wpsecscan_companion_scheduled_task_anomalies_callback( $request ) {
    global $wpdb;
    $rows = [];
    $as_table = $wpdb->prefix . 'actionscheduler_actions';
    if ( $wpdb->get_var( "SHOW TABLES LIKE '{$as_table}'" ) === $as_table ) {
        $raw = $wpdb->get_results(
            "SELECT hook, status, scheduled_date_gmt
               FROM {$as_table}
              WHERE scheduled_date_gmt > DATE_SUB( UTC_TIMESTAMP(), INTERVAL 7 DAY )
              ORDER BY scheduled_date_gmt DESC LIMIT 30",
            ARRAY_A
        );
        foreach ( (array) $raw as $r ) {
            $rows[] = [
                'hook'      => (string) $r['hook'],
                'status'    => (string) $r['status'],
                'scheduled' => (string) $r['scheduled_date_gmt'],
                'source'    => 'action-scheduler',
            ];
        }
    }
    // wp-cron: any hook whose next-run timestamp is within the next 7d
    // AND that doesn't match a known wp-core hook name (heuristic for
    // "newly added").
    $core_hooks = [
        'wp_version_check', 'wp_update_plugins', 'wp_update_themes',
        'wp_scheduled_delete', 'wp_scheduled_auto_draft_delete',
        'delete_expired_transients', 'wp_privacy_delete_old_export_files',
        'recovery_mode_clean_expired_keys', 'wp_https_detection',
        'do_pings',
    ];
    $cron = (array) _get_cron_array();
    $cutoff = time() + ( 7 * 86400 );
    foreach ( $cron as $ts => $hooks ) {
        if ( (int) $ts > $cutoff ) { continue; }
        foreach ( (array) $hooks as $hook_name => $args ) {
            if ( in_array( $hook_name, $core_hooks, true ) ) { continue; }
            $rows[] = [
                'hook'      => (string) $hook_name,
                'scheduled' => gmdate( 'c', (int) $ts ),
                'source'    => 'wp-cron-non-core',
            ];
        }
    }
    return rest_ensure_response( [
        'anomalies' => array_slice( $rows, 0, 50 ),
        'count'     => count( $rows ),
        'window_d'  => 7,
        'generated' => gmdate( 'c' ),
    ] );
}

/**
 * #20 — Cron-hook callbacks that reference shell-exec PHP functions.
 *
 * Walks the cron array, resolves each callback to a file via reflection,
 * grep-scans the source file for `exec()` / `shell_exec()` / `passthru()` /
 * `system()` / `popen()` / `proc_open()`. Returns the matching hooks with
 * the offending function names found nearby.
 */
function wpsecscan_companion_cron_shell_commands_callback( $request ) {
    $rows  = [];
    $cron  = (array) _get_cron_array();
    $bad_fns = [ 'exec', 'shell_exec', 'passthru', 'system', 'popen', 'proc_open' ];
    foreach ( $cron as $ts => $hooks ) {
        foreach ( (array) $hooks as $hook_name => $args ) {
            // _get_cron_array() gives only the hook name and args; resolve
            // via WP's registered callbacks for this hook.
            global $wp_filter;
            if ( ! isset( $wp_filter[ $hook_name ] ) ) { continue; }
            $hookobj = $wp_filter[ $hook_name ];
            $callbacks = is_object( $hookobj ) && isset( $hookobj->callbacks )
                ? $hookobj->callbacks
                : [];
            foreach ( $callbacks as $priority => $cbs ) {
                foreach ( (array) $cbs as $cb ) {
                    if ( ! is_array( $cb ) || ! isset( $cb['function'] ) ) {
                        continue;
                    }
                    $fn = $cb['function'];
                    $source_file = '';
                    try {
                        if ( is_string( $fn ) && function_exists( $fn ) ) {
                            $rf = new ReflectionFunction( $fn );
                            $source_file = (string) $rf->getFileName();
                        } elseif ( is_array( $fn ) && isset( $fn[1] ) ) {
                            $rm = new ReflectionMethod( $fn[0], $fn[1] );
                            $source_file = (string) $rm->getFileName();
                        } elseif ( $fn instanceof Closure ) {
                            $rc = new ReflectionFunction( $fn );
                            $source_file = (string) $rc->getFileName();
                        }
                    } catch ( Throwable $e ) {
                        continue;
                    }
                    if ( ! $source_file || ! file_exists( $source_file ) ) {
                        continue;
                    }
                    $size = @filesize( $source_file );
                    if ( $size === false || $size > 1024 * 1024 ) {
                        continue; // skip >1 MB files
                    }
                    $body = @file_get_contents( $source_file );
                    if ( ! $body ) { continue; }
                    $matches = [];
                    foreach ( $bad_fns as $bad ) {
                        // \b{bad}\s*\(  to avoid matching substrings.
                        if ( preg_match( '/\b' . preg_quote( $bad, '/' ) . '\s*\(/', $body ) ) {
                            $matches[] = $bad;
                        }
                    }
                    if ( $matches ) {
                        $rows[] = [
                            'hook'      => (string) $hook_name,
                            'source'    => ltrim( str_replace( ABSPATH, '', $source_file ), DIRECTORY_SEPARATOR ),
                            'functions' => $matches,
                        ];
                    }
                }
            }
        }
    }
    return rest_ensure_response( [
        'flagged'   => array_slice( $rows, 0, 50 ),
        'count'     => count( $rows ),
        'generated' => gmdate( 'c' ),
    ] );
}

/**
 * #19 — Last 50 lines of error_log with PII stripped.
 */
function wpsecscan_companion_php_error_log_tail_callback( $request ) {
    $log_path = (string) ini_get( 'error_log' );
    $lines    = [];
    if ( $log_path && file_exists( $log_path ) && is_readable( $log_path ) ) {
        // Read last ~80 KB to bound memory; split + tail-50.
        $size = filesize( $log_path );
        $f    = @fopen( $log_path, 'rb' );
        if ( $f ) {
            $offset = max( 0, $size - 80 * 1024 );
            @fseek( $f, $offset );
            $blob   = (string) @fread( $f, 80 * 1024 );
            @fclose( $f );
            $all    = preg_split( "/\r?\n/", $blob );
            $all    = array_filter( $all, function ( $l ) { return $l !== ''; } );
            $lines  = array_slice( array_values( $all ), -50 );
        }
    }
    // PII strip: emails, IPv4 addresses.
    $lines = array_map( function ( $l ) {
        $l = preg_replace( '/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/', '[EMAIL]', $l );
        $l = preg_replace( '/\b(?:\d{1,3}\.){3}\d{1,3}\b/',                            '[IP]',    $l );
        return $l;
    }, $lines );
    return rest_ensure_response( [
        'log_path'  => $log_path ?: '(not configured)',
        'lines'     => $lines,
        'count'     => count( $lines ),
        'generated' => gmdate( 'c' ),
    ] );
}
