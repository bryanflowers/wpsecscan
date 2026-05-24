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
