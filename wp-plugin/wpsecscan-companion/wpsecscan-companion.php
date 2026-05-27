<?php
/**
 * Plugin Name: WPSecScan companion
 * Plugin URI:  https://github.com/bryanflowers/wpsecscan
 * Description: Exposes a read-only, token-gated REST endpoint so the WPSecScan defensive scanner can pull authoritative diagnostics in one round-trip. No write actions.
 * Version:     1.4.0
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * Author:      Bryan
 * Author URI:  https://github.com/bryanflowers
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wpsecscan-companion
 * Domain Path: /languages
 *
 * @package WPSecScan_Companion
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WPSECSCAN_COMPANION_VERSION',     '1.4.0' );
define( 'WPSECSCAN_COMPANION_TOKEN_OPTION', 'wpsecscan_companion_token' );
define( 'WPSECSCAN_COMPANION_TOKEN_TTL',    60 * 60 );    // 60 minutes
define( 'WPSECSCAN_COMPANION_LOG_OPTION',   'wpsecscan_companion_log' );

require_once __DIR__ . '/includes/admin.php';
require_once __DIR__ . '/includes/rest.php';
require_once __DIR__ . '/includes/diagnostics.php';

/**
 * Bootstrap.
 */
add_action( 'plugins_loaded', 'wpsecscan_companion_load_textdomain' );
add_action( 'admin_menu',     'wpsecscan_companion_admin_menu' );
add_action( 'admin_init',     'wpsecscan_companion_admin_init' );
add_action( 'rest_api_init',  'wpsecscan_companion_register_routes' );
// #23: AJAX endpoint that powers the "Test connection" button on the
// admin page. Admin-only; doesn't expose anything an admin can't already see.
add_action( 'wp_ajax_wpsecscan_companion_test_connection', 'wpsecscan_companion_test_connection_ajax' );
// #31: wp_cron job to pre-compute the file-monitor manifest every 6 hours.
add_action( 'wpsecscan_companion_precompute_manifest_cron_hook', 'wpsecscan_companion_precompute_manifest_cron' );

/**
 * Load translations from /languages/<text-domain>-<locale>.mo
 */
function wpsecscan_companion_load_textdomain() {
    load_plugin_textdomain(
        'wpsecscan-companion',
        false,
        dirname( plugin_basename( __FILE__ ) ) . '/languages'
    );
}

/**
 * Activation: nothing to do — token is generated on demand from the admin page.
 */
register_activation_hook(   __FILE__, function () {
    add_option( WPSECSCAN_COMPANION_LOG_OPTION, [] );
    // #31 — schedule the manifest-precompute cron job (every 6h).
    if ( ! wp_next_scheduled( 'wpsecscan_companion_precompute_manifest_cron_hook' ) ) {
        wp_schedule_event( time() + 300, 'twicedaily', 'wpsecscan_companion_precompute_manifest_cron_hook' );
    }
} );

/**
 * Deactivation: revoke any active token + clear the cron job + transients.
 */
register_deactivation_hook( __FILE__, function () {
    delete_option( WPSECSCAN_COMPANION_TOKEN_OPTION );
    wp_clear_scheduled_hook( 'wpsecscan_companion_precompute_manifest_cron_hook' );
    delete_transient( 'wpsecscan_companion_file_manifest' );
    delete_transient( 'wpsecscan_companion_file_manifest_full' );
} );

/**
 * Uninstall: see uninstall.php — wipes options.
 */
