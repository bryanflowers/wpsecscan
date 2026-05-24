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
 * Handle POSTs from the admin page (generate / revoke token).
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
    }
}

/**
 * Generate + store a one-time token with timestamp.
 */
function wpsecscan_companion_generate_token() {
    $token = wp_generate_password( 48, false, false );
    update_option(
        WPSECSCAN_COMPANION_TOKEN_OPTION,
        [
            'token'   => wp_hash_password( $token ),  // store HASH, not plaintext
            'created' => time(),
            'used'    => false,
        ],
        false // not autoload
    );
    set_transient( 'wpsecscan_companion_token_plain', $token, 30 ); // show plain once
    add_settings_error( 'wpsecscan-companion', 'generated', 'Token generated. Copy it now — it will not be shown again.', 'updated' );
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
