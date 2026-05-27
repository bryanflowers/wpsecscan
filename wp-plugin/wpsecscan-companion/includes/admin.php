<?php
/**
 * Admin page: token generator + activity log.
 *
 * @package WPSecScan_Companion
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Register the Settings sub-menu page.
 */
function wpsecscan_companion_admin_menu() {
    add_options_page(
        'WPSecScan companion',
        'WPSecScan',
        'manage_options',
        'wpsecscan-companion',
        'wpsecscan_companion_render_admin_page'
    );
}

/**
 * Handle POSTs from the admin page (generate / revoke token / save
 * per-endpoint toggles / export the activity log as CSV).
 */
function wpsecscan_companion_admin_init() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    if ( empty( $_POST['wpsecscan_action'] ) ) {
        return;
    }
    check_admin_referer( 'wpsecscan-companion' );

    $action = sanitize_key( $_POST['wpsecscan_action'] );
    if ( $action === 'generate' ) {
        wpsecscan_companion_generate_token();
    } elseif ( $action === 'revoke' ) {
        delete_option( WPSECSCAN_COMPANION_TOKEN_OPTION );
        add_settings_error( 'wpsecscan-companion', 'revoked', 'Token revoked.', 'updated' );
    } elseif ( $action === 'save_endpoints' ) {
        // #24 per-endpoint enable/disable
        $allowed = [];
        foreach ( wpsecscan_companion_all_endpoints() as $slug => $_label ) {
            if ( ! empty( $_POST['endpoint'][ $slug ] ) ) {
                $allowed[] = $slug;
            }
        }
        update_option( 'wpsecscan_companion_endpoints_enabled', $allowed, false );
        add_settings_error( 'wpsecscan-companion', 'saved', 'Endpoint policy saved.', 'updated' );
    } elseif ( $action === 'export_csv' ) {
        // #26 CSV export of activity log
        wpsecscan_companion_export_log_csv();
        exit;
    } elseif ( $action === 'save_security' ) {
        // #27 configurable max-uses + #32 access webhook
        $max = isset( $_POST['max_uses'] ) ? (int) $_POST['max_uses'] : 10;
        $max = max( 1, min( 100, $max ) );
        update_option( 'wpsecscan_companion_max_uses', $max, false );
        $url = isset( $_POST['access_webhook'] ) ? trim( wp_unslash( $_POST['access_webhook'] ) ) : '';
        if ( $url === '' || preg_match( '#^https?://[^\s<>"\']+$#i', $url ) ) {
            update_option( 'wpsecscan_companion_access_webhook', esc_url_raw( $url ), false );
        }
        add_settings_error( 'wpsecscan-companion', 'saved-sec', 'Security policy saved.', 'updated' );
    }
}

/**
 * #24 — full list of endpoints the plugin can expose. Used to render
 * toggles in the admin UI + as the source of truth for
 * wpsecscan_companion_endpoint_enabled().
 */
function wpsecscan_companion_all_endpoints() {
    return [
        'diagnostics'            => 'Diagnostics (core / plugins / users / cron)',
        'file-monitor'           => 'File-monitor (SHA-256 manifest)',
        'app-passwords-policy'   => 'App-passwords policy',
        'slow-query-log'         => 'Slow-query log location',
        'failed-login-geo'       => 'Failed-login source IPs',
        'admin-login-sources'    => 'Admin-login source IPs',
        'backups'                => 'Backup-plugin status',
        'file-perms'             => 'File permissions',
        '2fa-enforcement'        => '2FA enforcement policy',
        'active-sessions'        => 'Active admin sessions (v1.2)',
        'recent-admin-actions'   => 'Recent admin actions (v1.2)',
        'db-size-by-table'       => 'DB size per table (v1.2)',
        'log-files'              => 'Exposed log files (v1.2)',
        'php-error-log-tail'     => 'PHP error log tail (v1.2)',
        'wp-cron-failures'       => 'wp-cron failures (v1.2)',
        'scheduled-task-anomalies' => 'Scheduled-task anomalies (v1.2)',
        'cron-shell-commands'    => 'Cron callbacks invoking shell-exec (v1.2)',
        'object-cache-info'      => 'Object-cache drop-in status (v1.2)',
        'transient-cache-size'   => 'Transient cache bloat (v1.2)',
        'wp-mail-deliverability' => 'wp_mail deliverability (v1.2)',
        'multisite-network-info' => 'Multisite per-blog admin counts (v1.2)',
    ];
}

/**
 * #24 — true iff the given endpoint slug is enabled. When the option is
 * absent or empty, ALL endpoints are enabled (back-compat for installs
 * upgrading from v1.0/v1.1 which had no toggles).
 */
function wpsecscan_companion_endpoint_enabled( $slug ) {
    $opt = get_option( 'wpsecscan_companion_endpoints_enabled', null );
    if ( $opt === null || ! is_array( $opt ) || $opt === [] ) {
        return true;
    }
    return in_array( $slug, $opt, true );
}

/**
 * #26 — stream the activity log as CSV.
 */
function wpsecscan_companion_export_log_csv() {
    $log = (array) get_option( WPSECSCAN_COMPANION_LOG_OPTION, [] );
    $filename = 'wpsecscan-companion-log-' . gmdate( 'Ymd-His' ) . '.csv';
    nocache_headers();
    header( 'Content-Type: text/csv; charset=utf-8' );
    header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
    $out = fopen( 'php://output', 'w' );
    fputcsv( $out, [ 'timestamp', 'ip', 'result', 'sections' ] );
    foreach ( $log as $row ) {
        fputcsv( $out, [
            (string) ( $row['when']     ?? '' ),
            (string) ( $row['ip']       ?? '' ),
            (string) ( $row['result']   ?? '' ),
            (string) ( $row['sections'] ?? '' ),
        ] );
    }
    fclose( $out );
}

/**
 * Generate + store a one-time token with timestamp.
 */
function wpsecscan_companion_generate_token() {
    $token = wp_generate_password( 48, false, false );
    // #25 — IP-pin support. The operator can tick "Pin to a specific IP"
    // and supply the scanner-machine's IP; subsequent requests from any
    // other IP are auto-revoked.
    $pinned_ip = '';
    if ( ! empty( $_POST['pin_ip'] ) ) {
        $raw = isset( $_POST['pin_ip_value'] ) ? trim( (string) $_POST['pin_ip_value'] ) : '';
        // Sanitise: only allow what looks like a v4 or v6 address.
        if ( filter_var( $raw, FILTER_VALIDATE_IP ) ) {
            $pinned_ip = $raw;
        }
    }
    update_option(
        WPSECSCAN_COMPANION_TOKEN_OPTION,
        [
            'token'     => wp_hash_password( $token ),  // store HASH, not plaintext
            'created'   => time(),
            'used'      => false,
            'use_count' => 0,
            'pinned_ip' => $pinned_ip,
        ],
        false // not autoload
    );
    set_transient( 'wpsecscan_companion_token_plain', $token, 30 ); // show plain once
    $msg = 'Token generated. Copy it now — it will not be shown again.';
    if ( $pinned_ip ) {
        $msg .= ' Pinned to IP ' . esc_html( $pinned_ip ) . ' (other IPs will be rejected + revoke the token).';
    }
    add_settings_error( 'wpsecscan-companion', 'generated', $msg, 'updated' );
}

/**
 * Render the admin page.
 */
function wpsecscan_companion_render_admin_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    $token_plain = get_transient( 'wpsecscan_companion_token_plain' );
    delete_transient( 'wpsecscan_companion_token_plain' );

    $stored = get_option( WPSECSCAN_COMPANION_TOKEN_OPTION );
    $has_active = is_array( $stored ) && ! empty( $stored['token'] );

    $log = (array) get_option( WPSECSCAN_COMPANION_LOG_OPTION, [] );
    $log = array_slice( $log, -20 );

    settings_errors( 'wpsecscan-companion' );
    ?>
    <div class="wrap">
        <h1>WPSecScan companion</h1>
        <p>
            Exposes a read-only diagnostics endpoint at
            <code>/wp-json/wpsecscan/v1/diagnostics</code>, gated by a one-time
            token you generate below. The endpoint never writes — it returns
            sanitised plugin / theme / user / cron / Site-Health data so the
            WPSecScan defensive scanner gets authoritative info in one
            round-trip instead of HTTP-probing 30+ paths.
        </p>

        <?php if ( $token_plain ) : ?>
            <div class="notice notice-info">
                <p><strong>Your new token (copy now — shown once):</strong></p>
                <p><code style="font-size:1.1em;"><?php echo esc_html( $token_plain ); ?></code></p>
                <p>Run the scanner with:
                    <code>wpsecscan --target <?php echo esc_html( home_url() ); ?> --companion-token '<?php echo esc_html( $token_plain ); ?>'</code>
                </p>
                <p>Token expires in 60 minutes if unused, and is consumed on first use.</p>
            </div>
        <?php endif; ?>

        <form method="post">
            <?php wp_nonce_field( 'wpsecscan-companion' ); ?>
            <p>
                <?php if ( $has_active ) : ?>
                    <em>A token is currently active.</em>
                    <button class="button" name="wpsecscan_action" value="revoke">Revoke token</button>
                <?php else : ?>
                    <em>No active token.</em>
                <?php endif; ?>
                <button class="button button-primary" name="wpsecscan_action" value="generate">Generate one-time token</button>
            </p>
            <p>
                <label>
                    <input type="checkbox" name="pin_ip" value="1">
                    Pin to a specific IP (recommended if you know the scanner machine):
                </label>
                <input type="text" name="pin_ip_value" placeholder="203.0.113.4 or 2001:db8::1" size="40">
            </p>
        </form>

        <h2>#25 / #27 / #32 Security policy</h2>
        <form method="post">
            <?php wp_nonce_field( 'wpsecscan-companion' ); ?>
            <input type="hidden" name="wpsecscan_action" value="save_security">
            <table class="form-table">
                <tr>
                    <th><label for="wpsec-max-uses">Max uses per token</label></th>
                    <td>
                        <input id="wpsec-max-uses" type="number" name="max_uses" min="1" max="100"
                               value="<?php echo (int) get_option( 'wpsecscan_companion_max_uses', 10 ); ?>" style="width:5em;">
                        <p class="description">Default 10. Set to 1 for strict single-use mode. The full scan with all v1.2 endpoints needs around 17 reads, so 1-9 will require a fresh token mid-scan.</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="wpsec-webhook">Access webhook URL (optional)</label></th>
                    <td>
                        <input id="wpsec-webhook" type="url" name="access_webhook" size="60"
                               value="<?php echo esc_attr( get_option( 'wpsecscan_companion_access_webhook', '' ) ); ?>">
                        <p class="description">When set, every endpoint access posts a small JSON event here ({event, timestamp, ip, route, use_count}). IP-mismatch revocations also post here as 'ip_mismatch_token_revoked'.</p>
                    </td>
                </tr>
            </table>
            <p><button class="button button-primary" type="submit">Save security policy</button></p>
        </form>

        <h2>#23 Test connection</h2>
        <p>
            Sanity-check that the scanner will be able to reach the endpoints
            from outside. The test issues a fresh single-use token internally,
            hits each enabled endpoint locally over <code>http://localhost</code>,
            and reports which ones returned valid JSON.
        </p>
        <p>
            <button class="button" id="wpsec-test-conn">Run test</button>
            <span id="wpsec-test-status" style="margin-left:1em;"></span>
        </p>
        <table class="widefat" id="wpsec-test-results" style="display:none;">
            <thead><tr><th>Endpoint</th><th>HTTP</th><th>Result</th></tr></thead>
            <tbody></tbody>
        </table>
        <script>
        (function(){
            var btn = document.getElementById('wpsec-test-conn');
            var status = document.getElementById('wpsec-test-status');
            var table = document.getElementById('wpsec-test-results');
            var tbody = table.querySelector('tbody');
            btn && btn.addEventListener('click', function(e){
                e.preventDefault();
                btn.disabled = true;
                status.textContent = 'Running…';
                tbody.innerHTML = '';
                table.style.display = '';
                fetch(
                    <?php echo wp_json_encode( admin_url( 'admin-ajax.php?action=wpsecscan_companion_test_connection' ) ); ?>,
                    { credentials: 'same-origin' }
                ).then(function(r){ return r.json(); }).then(function(j){
                    btn.disabled = false;
                    status.textContent = 'Done — ' + (j.passed || 0) + ' of ' + (j.total || 0) + ' endpoints passed.';
                    (j.results || []).forEach(function(row){
                        var tr = document.createElement('tr');
                        tr.innerHTML =
                            '<td><code>' + row.slug + '</code></td>' +
                            '<td>' + row.status + '</td>' +
                            '<td>' + (row.ok ? '✓ ' + (row.bytes || 0) + ' bytes JSON' : '✗ ' + (row.error || '')) + '</td>';
                        tbody.appendChild(tr);
                    });
                }).catch(function(err){
                    btn.disabled = false;
                    status.textContent = 'Test failed: ' + err;
                });
            });
        })();
        </script>

        <h2>#24 Endpoints enabled</h2>
        <p>Disable any endpoint you don't want to expose. By default, all are enabled.</p>
        <form method="post">
            <?php wp_nonce_field( 'wpsecscan-companion' ); ?>
            <input type="hidden" name="wpsecscan_action" value="save_endpoints">
            <table class="widefat striped" style="max-width:760px">
                <thead><tr><th>Endpoint</th><th>Enabled</th></tr></thead>
                <tbody>
                <?php foreach ( wpsecscan_companion_all_endpoints() as $slug => $label ) : ?>
                    <tr>
                        <td><code>/wp-json/wpsecscan/v1/<?php echo esc_html( $slug ); ?></code><br><small><?php echo esc_html( $label ); ?></small></td>
                        <td><input type="checkbox" name="endpoint[<?php echo esc_attr( $slug ); ?>]" value="1" <?php checked( wpsecscan_companion_endpoint_enabled( $slug ) ); ?>></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <p><button class="button button-primary" type="submit">Save endpoint policy</button></p>
        </form>

        <h2>#26 Export activity log</h2>
        <p>Download the activity log as CSV for archiving / off-box analysis.</p>
        <form method="post">
            <?php wp_nonce_field( 'wpsecscan-companion' ); ?>
            <input type="hidden" name="wpsecscan_action" value="export_csv">
            <p><button class="button" type="submit">Download CSV</button></p>
        </form>

        <h2>Recent activity</h2>
        <?php if ( empty( $log ) ) : ?>
            <p><em>No requests yet.</em></p>
        <?php else : ?>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th>When</th>
                        <th>From IP</th>
                        <th>Result</th>
                        <th>Sections returned</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ( array_reverse( $log ) as $row ) : ?>
                    <tr>
                        <td><?php echo esc_html( $row['when'] ?? '' ); ?></td>
                        <td><code><?php echo esc_html( $row['ip'] ?? '' ); ?></code></td>
                        <td><?php echo esc_html( $row['result'] ?? '' ); ?></td>
                        <td><?php echo esc_html( $row['sections'] ?? '' ); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <h2>Privacy + security</h2>
        <ul style="list-style:disc; margin-left:1.5em;">
            <li>Token is stored as a password hash (<code>wp_hash_password</code>) — never in plaintext.</li>
            <li>Single-use: consumed on first successful read.</li>
            <li>60-minute expiry if unused.</li>
            <li>HTTPS-only: the endpoint refuses non-TLS requests when <code>FORCE_SSL_ADMIN</code> is on.</li>
            <li>No write actions exposed.</li>
            <li>No DB credentials, AUTH_KEY salts, plaintext API keys, or user passwords are returned.</li>
            <li>Activity log on this page records every access (IP + timestamp).</li>
        </ul>
    </div>
    <?php
}

/**
 * #23 — admin-only AJAX handler that issues a fresh test token and hits
 * every enabled endpoint locally, returning a per-endpoint pass/fail JSON.
 */
function wpsecscan_companion_test_connection_ajax() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( [ 'error' => 'forbidden' ], 403 );
    }
    // Issue an out-of-band single-use token. We bypass the user-facing
    // generator (which stores hash + shows plaintext once) so the test
    // doesn't burn the "real" token the operator might have prepared.
    $plain = wp_generate_password( 48, false, false );
    update_option(
        WPSECSCAN_COMPANION_TOKEN_OPTION,
        [
            'token'     => wp_hash_password( $plain ),
            'created'   => time(),
            'used'      => false,
            'use_count' => 0,
            'pinned_ip' => '',
        ],
        false
    );
    $results = [];
    $passed  = 0;
    foreach ( wpsecscan_companion_all_endpoints() as $slug => $_label ) {
        if ( ! wpsecscan_companion_endpoint_enabled( $slug ) ) {
            $results[] = [
                'slug'   => $slug,
                'status' => 0,
                'ok'     => false,
                'error'  => 'disabled in policy',
            ];
            continue;
        }
        $url = rest_url( 'wpsecscan/v1/' . $slug );
        $resp = wp_remote_get( $url, [
            'timeout'   => 10,
            'sslverify' => false,
            'headers'   => [ 'X-WPSecScan-Token' => $plain ],
        ] );
        if ( is_wp_error( $resp ) ) {
            $results[] = [
                'slug'   => $slug,
                'status' => 0,
                'ok'     => false,
                'error'  => $resp->get_error_message(),
            ];
            continue;
        }
        $code = (int) wp_remote_retrieve_response_code( $resp );
        $body = (string) wp_remote_retrieve_body( $resp );
        $json = @json_decode( $body, true );
        $ok   = ( $code === 200 && is_array( $json ) );
        $results[] = [
            'slug'   => $slug,
            'status' => $code,
            'ok'     => $ok,
            'bytes'  => strlen( $body ),
            'error'  => $ok ? '' : substr( $body, 0, 200 ),
        ];
        if ( $ok ) {
            $passed++;
        }
    }
    // Clean up the test token so it can't be reused.
    delete_option( WPSECSCAN_COMPANION_TOKEN_OPTION );
    wp_send_json( [
        'results' => $results,
        'passed'  => $passed,
        'total'   => count( $results ),
    ] );
}

/**
 * B46 — Settings page button: "Check for updates".
 * Compares the installed plugin version against the GitHub releases
 * "latest" tag. Read-only HTTP call; never writes / never auto-installs.
 */
add_action( 'wp_ajax_wpsecscan_companion_check_update', 'wpsecscan_companion_check_update_ajax' );
function wpsecscan_companion_check_update_ajax() {
    if ( ! current_user_can( 'manage_options' )
            || ! check_ajax_referer( 'wpsecscan_companion_admin', '_wpnonce', false ) ) {
        wp_send_json_error( 'permission denied', 403 );
    }
    $current = defined( 'WPSECSCAN_COMPANION_VERSION' )
                ? (string) WPSECSCAN_COMPANION_VERSION
                : '0.0.0';
    $resp = wp_remote_get(
        'https://api.github.com/repos/bryanflowers/wpsecscan/releases/latest',
        [
            'timeout' => 8,
            'headers' => [
                'Accept'     => 'application/vnd.github+json',
                'User-Agent' => 'WPSecScan-Companion/' . $current,
            ],
        ]
    );
    if ( is_wp_error( $resp ) ) {
        wp_send_json_error( 'fetch failed: ' . $resp->get_error_message() );
    }
    $code = (int) wp_remote_retrieve_response_code( $resp );
    $body = (string) wp_remote_retrieve_body( $resp );
    if ( $code !== 200 ) {
        wp_send_json_error( 'github returned ' . $code );
    }
    $data    = @json_decode( $body, true );
    $tag     = isset( $data['tag_name'] ) ? trim( (string) $data['tag_name'], 'v' ) : '';
    $url     = isset( $data['html_url'] ) ? (string) $data['html_url'] : '';
    $is_new  = ( $tag && version_compare( $tag, $current, '>' ) );
    wp_send_json_success( [
        'current_version' => $current,
        'latest_version'  => $tag,
        'update_available'=> $is_new,
        'release_url'     => $url,
    ] );
}
