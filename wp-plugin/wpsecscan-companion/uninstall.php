<?php
/**
 * Uninstall — wipe options on plugin delete.
 *
 * @package WPSecScan_Companion
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

delete_option( 'wpsecscan_companion_token' );
delete_option( 'wpsecscan_companion_log' );
delete_transient( 'wpsecscan_companion_token_plain' );
