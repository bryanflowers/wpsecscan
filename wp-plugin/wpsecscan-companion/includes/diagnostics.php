<?php
/**
 * Build the sanitised diagnostics payload.
 *
 * @package WPSecScan_Companion
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Return the diagnostics payload for the REST callback.
 *
 * @return array
 */
function wpsecscan_companion_build_diagnostics() {
    return [
        'core'             => wpsecscan_companion_core(),
        'plugins'          => wpsecscan_companion_plugins(),
        'themes'           => wpsecscan_companion_themes(),
        'users'            => wpsecscan_companion_users(),
        'cron'             => wpsecscan_companion_cron(),
        'auth_filters'     => wpsecscan_companion_auth_filters(),
        'site_health'      => wpsecscan_companion_site_health(),
        'config_constants' => wpsecscan_companion_constants(),
        'companion'        => [
            'version'    => WPSECSCAN_COMPANION_VERSION,
            'gathered_at' => gmdate( 'c' ),
        ],
    ];
}

/**
 * Core info.
 */
function wpsecscan_companion_core() {
    global $wp_version;
    return [
        'version'    => $wp_version,
        'multisite'  => is_multisite(),
        'language'   => get_locale(),
        'php'        => PHP_VERSION,
        'mysql'      => function_exists( 'mysqli_get_client_info' ) ? mysqli_get_client_info() : '?',
        'siteurl'    => get_option( 'siteurl' ),
        'home'       => get_option( 'home' ),
        'is_ssl'     => is_ssl(),
    ];
}

/**
 * Plugins — slug, version, active, file_hash_sha256 of the main file, update_available.
 */
function wpsecscan_companion_plugins() {
    if ( ! function_exists( 'get_plugins' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $all     = get_plugins();
    $updates = get_site_transient( 'update_plugins' );
    $update_response = ( $updates && isset( $updates->response ) ) ? $updates->response : [];

    $out = [];
    foreach ( $all as $file => $data ) {
        $slug = dirname( $file );
        if ( '.' === $slug || '' === $slug ) {
            $slug = basename( $file, '.php' );
        }
        $full = WP_PLUGIN_DIR . '/' . $file;
        $hash = is_readable( $full ) ? hash_file( 'sha256', $full ) : null;
        $out[] = [
            'slug'             => $slug,
            'file'             => $file,
            'name'             => $data['Name'] ?? '',
            'version'          => $data['Version'] ?? '',
            'active'           => is_plugin_active( $file ),
            'file_hash_sha256' => $hash,
            'update_available' => isset( $update_response[ $file ] ),
        ];
    }
    return $out;
}

/**
 * Themes — slug, version, active, file_hash_sha256 of style.css, parent.
 */
function wpsecscan_companion_themes() {
    $themes        = wp_get_themes();
    $current       = wp_get_theme();
    $current_stylesheet = $current ? $current->get_stylesheet() : '';
    $updates       = get_site_transient( 'update_themes' );
    $update_resp   = ( $updates && isset( $updates->response ) ) ? $updates->response : [];

    $out = [];
    foreach ( $themes as $slug => $theme ) {
        $stylecss = $theme->get_stylesheet_directory() . '/style.css';
        $hash     = is_readable( $stylecss ) ? hash_file( 'sha256', $stylecss ) : null;
        $out[] = [
            'slug'             => $slug,
            'name'             => $theme->get( 'Name' ),
            'version'          => $theme->get( 'Version' ),
            'active'           => ( $slug === $current_stylesheet ),
            'parent'           => $theme->parent() ? $theme->parent()->get_stylesheet() : null,
            'file_hash_sha256' => $hash,
            'update_available' => isset( $update_resp[ $slug ] ),
        ];
    }
    return $out;
}

/**
 * Users — login + email hash + roles + 2fa_enabled best-effort.
 */
function wpsecscan_companion_users() {
    $users = get_users( [
        'fields' => [ 'ID', 'user_login', 'user_email', 'user_registered' ],
        'number' => 500,
    ] );
    $out = [];
    foreach ( $users as $u ) {
        $wpu        = get_user_by( 'id', $u->ID );
        $roles      = $wpu ? $wpu->roles : [];
        $email_hash = $u->user_email ? hash( 'sha256', strtolower( trim( $u->user_email ) ) ) : null;
        $last_login = (int) get_user_meta( $u->ID, 'last_login', true );

        // 2FA detection — best-effort, looks for common plugin meta keys.
        $two_fa = false;
        foreach ( [ '_two_factor_enabled_providers', 'totp_secret', 'wfls-totp', 'duo_two_factor_token' ] as $k ) {
            if ( get_user_meta( $u->ID, $k, true ) ) {
                $two_fa = true;
                break;
            }
        }

        $out[] = [
            'id'         => $u->ID,
            'login'      => $u->user_login,
            'email_hash' => $email_hash,
            'roles'      => $roles,
            'registered' => $u->user_registered,
            'last_login' => $last_login ?: null,
            '2fa_enabled'=> $two_fa,
        ];
    }
    return $out;
}

/**
 * Cron — hooks + next run + recurrence + source plugin guess.
 */
function wpsecscan_companion_cron() {
    $crons = _get_cron_array();
    $out   = [];
    if ( ! is_array( $crons ) ) {
        return $out;
    }
    foreach ( $crons as $ts => $hooks ) {
        foreach ( $hooks as $hook => $events ) {
            foreach ( $events as $key => $event ) {
                $out[] = [
                    'hook'     => $hook,
                    'next_run' => (int) $ts,
                    'schedule' => $event['schedule'] ?? false,
                ];
            }
        }
    }
    return $out;
}

/**
 * Auth filters — which plugin code has hooked the authentication chain.
 */
function wpsecscan_companion_auth_filters() {
    global $wp_filter;
    $tracked = [ 'authenticate', 'wp_authenticate', 'login_form', 'check_passwords' ];
    $out     = [];
    foreach ( $tracked as $hook ) {
        if ( empty( $wp_filter[ $hook ] ) ) {
            $out[ $hook ] = [];
            continue;
        }
        $callbacks = [];
        foreach ( $wp_filter[ $hook ]->callbacks as $priority => $cb_list ) {
            foreach ( $cb_list as $cb ) {
                $fn = $cb['function'] ?? null;
                if ( is_string( $fn ) ) {
                    $callbacks[] = "{$priority}:{$fn}";
                } elseif ( is_array( $fn ) && count( $fn ) === 2 ) {
                    $obj = is_object( $fn[0] ) ? get_class( $fn[0] ) : (string) $fn[0];
                    $callbacks[] = "{$priority}:{$obj}::{$fn[1]}";
                } else {
                    $callbacks[] = "{$priority}:Closure";
                }
            }
        }
        $out[ $hook ] = $callbacks;
    }
    return $out;
}

/**
 * Site Health — pull critical issues.
 */
function wpsecscan_companion_site_health() {
    if ( ! class_exists( 'WP_Site_Health' ) ) {
        require_once ABSPATH . 'wp-admin/includes/class-wp-site-health.php';
    }
    if ( ! class_exists( 'WP_Site_Health' ) ) {
        return [ 'critical' => [], 'recommended' => [] ];
    }
    $sh   = WP_Site_Health::get_instance();
    $tests = method_exists( $sh, 'get_tests' ) ? $sh->get_tests() : [ 'direct' => [], 'async' => [] ];

    $out  = [ 'critical' => [], 'recommended' => [] ];
    foreach ( $tests['direct'] ?? [] as $test ) {
        if ( empty( $test['test'] ) ) {
            continue;
        }
        $fn = is_array( $test['test'] ) ? $test['test'] : [ $sh, "get_test_{$test['test']}" ];
        if ( ! is_callable( $fn ) ) {
            continue;
        }
        try {
            $result = call_user_func( $fn );
            if ( is_array( $result ) && ! empty( $result['status'] ) ) {
                $bucket = $result['status'] === 'critical' ? 'critical' : ( $result['status'] === 'recommended' ? 'recommended' : null );
                if ( $bucket ) {
                    $out[ $bucket ][] = [
                        'label'       => $result['label'] ?? '',
                        'description' => wp_strip_all_tags( $result['description'] ?? '' ),
                    ];
                }
            }
        } catch ( Throwable $e ) {
            // Ignore one broken test
        }
    }
    return $out;
}

/**
 * Sanitised wp-config constants. Skip secrets.
 */
function wpsecscan_companion_constants() {
    $safe = [
        'WP_DEBUG', 'WP_DEBUG_DISPLAY', 'WP_DEBUG_LOG', 'WP_AUTO_UPDATE_CORE',
        'AUTOMATIC_UPDATER_DISABLED', 'WP_HTTP_BLOCK_EXTERNAL', 'WP_POST_REVISIONS',
        'DISALLOW_FILE_EDIT', 'DISALLOW_FILE_MODS', 'FORCE_SSL_ADMIN',
        'WP_MEMORY_LIMIT', 'WP_MAX_MEMORY_LIMIT', 'CONCATENATE_SCRIPTS',
        'WP_CACHE', 'WP_CONTENT_DIR', 'COOKIE_DOMAIN',
    ];
    $out = [];
    foreach ( $safe as $k ) {
        if ( defined( $k ) ) {
            $v = constant( $k );
            // Defensive — never return paths that contain creds or secrets
            $out[ $k ] = is_scalar( $v ) ? $v : '<' . gettype( $v ) . '>';
        }
    }
    return $out;
}
