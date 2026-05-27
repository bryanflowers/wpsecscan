<?php
/**
 * B48 — WP-CLI integration: `wp wpsec` commands.
 *
 * Registers a `wp wpsec` namespace with helper subcommands so operators
 * with shell access can use the companion plugin without an external
 * scanner. Embedded subset only; the full scanner remains the Python
 * tool published on PyPI.
 *
 * Subcommands:
 *   wp wpsec info               Print plugin version + endpoint allow-list
 *   wp wpsec token              Issue a fresh one-shot token
 *   wp wpsec endpoint-test      Hit every enabled endpoint locally
 *   wp wpsec self-check         Run WP Site Health direct tests; non-zero on critical
 *   wp wpsec scan-instructions  Print the canonical `wpsecscan URL --companion-token ...`
 *
 * @package WPSecScan_Companion
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
    return;
}

class WPSecScan_Companion_CLI {

    /**
     * Print plugin version + enabled-endpoint list.
     *
     * ## EXAMPLES
     *
     *     $ wp wpsec info
     */
    public function info( $args, $assoc_args ) {
        WP_CLI::log( 'wpsecscan-companion ' . WPSECSCAN_COMPANION_VERSION );
        $enabled = [];
        if ( function_exists( 'wpsecscan_companion_all_endpoints' ) ) {
            foreach ( wpsecscan_companion_all_endpoints() as $slug => $_label ) {
                if ( function_exists( 'wpsecscan_companion_endpoint_enabled' )
                        && wpsecscan_companion_endpoint_enabled( $slug ) ) {
                    $enabled[] = $slug;
                }
            }
        }
        WP_CLI::log( sprintf( 'enabled endpoints (%d):', count( $enabled ) ) );
        foreach ( $enabled as $slug ) {
            WP_CLI::log( '  /wp-json/wpsecscan/v1/' . $slug );
        }
    }

    /**
     * Issue a fresh one-shot token and print it. Token is wiped after
     * one use (or 10 uses, depending on Settings).
     *
     * ## EXAMPLES
     *
     *     $ wp wpsec token
     */
    public function token( $args, $assoc_args ) {
        $token = wp_generate_password( 32, false, false );
        // S3 (v2.7.1) — the canonical key in rest.php's check_token() is
        // 'created' (not 'created_at'). The previous mismatch made every
        // CLI-issued token compute time() - 0 > TTL, so the token was
        // always expired — `wp wpsec token` was completely broken.
        $stored = [
            'token'      => wp_hash_password( $token ),
            'created'    => time(),
            'use_count'  => 0,
        ];
        update_option( WPSECSCAN_COMPANION_TOKEN_OPTION, $stored, false );
        WP_CLI::log( $token );
        WP_CLI::log( '' );
        WP_CLI::log( '# Use it like:' );
        WP_CLI::log( '#   wpsecscan ' . get_site_url() . ' --companion-token ' . $token );
    }

    /**
     * Hit every enabled endpoint locally + print pass/fail.
     *
     * ## EXAMPLES
     *
     *     $ wp wpsec endpoint-test
     */
    public function endpoint_test( $args, $assoc_args ) {
        $token = wp_generate_password( 32, false, false );
        update_option( WPSECSCAN_COMPANION_TOKEN_OPTION, [
            'token'      => wp_hash_password( $token ),
            'created'    => time(),  // S3: canonical key per rest.php
            'use_count'  => 0,
        ], false );
        $passed = 0;
        $total = 0;
        if ( function_exists( 'wpsecscan_companion_all_endpoints' ) ) {
            foreach ( wpsecscan_companion_all_endpoints() as $slug => $_label ) {
                if ( ! ( function_exists( 'wpsecscan_companion_endpoint_enabled' )
                            && wpsecscan_companion_endpoint_enabled( $slug ) ) ) {
                    continue;
                }
                $total++;
                $url = get_rest_url( null, 'wpsecscan/v1/' . $slug );
                $resp = wp_remote_get( $url, [
                    'timeout' => 10,
                    'headers' => [ 'X-WPSecScan-Token' => $token ],
                ] );
                if ( ! is_wp_error( $resp ) && (int) wp_remote_retrieve_response_code( $resp ) === 200 ) {
                    WP_CLI::log( sprintf( '  ✓ %-40s 200 OK', $slug ) );
                    $passed++;
                } else {
                    $err = is_wp_error( $resp )
                        ? $resp->get_error_message()
                        : (int) wp_remote_retrieve_response_code( $resp );
                    WP_CLI::log( sprintf( '  ✗ %-40s %s', $slug, $err ) );
                }
            }
        }
        delete_option( WPSECSCAN_COMPANION_TOKEN_OPTION );
        WP_CLI::log( sprintf( '%d / %d endpoints OK', $passed, $total ) );
        if ( $passed !== $total ) {
            WP_CLI::halt( 1 );
        }
    }

    /**
     * Run WP core Site Health direct tests + exit non-zero on critical.
     *
     * ## EXAMPLES
     *
     *     $ wp wpsec self-check
     */
    public function self_check( $args, $assoc_args ) {
        if ( ! class_exists( 'WP_Site_Health' ) ) {
            require_once ABSPATH . 'wp-admin/includes/class-wp-site-health.php';
        }
        if ( ! class_exists( 'WP_Site_Health' ) ) {
            WP_CLI::error( 'WP_Site_Health unavailable in this WP version' );
        }
        $sh = WP_Site_Health::get_instance();
        $tests = $sh->get_tests();
        $critical = 0;
        foreach ( [ 'direct' ] as $kind ) {
            foreach ( (array) ( $tests[ $kind ] ?? [] ) as $name => $t ) {
                $cb = $t['test'] ?? null;
                if ( ! is_callable( $cb ) ) { continue; }
                try {
                    $r = call_user_func( $cb );
                    $status = (string) ( $r['status'] ?? '' );
                    if ( $status === 'critical' ) {
                        $critical++;
                        WP_CLI::log( sprintf( '  ! %s — %s', $name, $r['label'] ?? '' ) );
                    } elseif ( $status === 'recommended' ) {
                        WP_CLI::log( sprintf( '  ~ %s — %s', $name, $r['label'] ?? '' ) );
                    }
                } catch ( Throwable $e ) {
                    // ignore
                }
            }
        }
        WP_CLI::log( sprintf( '%d critical, summary at /wp-admin/site-health.php', $critical ) );
        if ( $critical > 0 ) {
            WP_CLI::halt( 1 );
        }
    }

    /**
     * Print the canonical wpsecscan invocation for this site.
     *
     * ## EXAMPLES
     *
     *     $ wp wpsec scan-instructions
     */
    public function scan_instructions( $args, $assoc_args ) {
        WP_CLI::log( '# The full scanner lives outside WordPress. Install via pip:' );
        WP_CLI::log( '#' );
        WP_CLI::log( '#   pip install wpsecscan' );
        WP_CLI::log( '#' );
        WP_CLI::log( '# Then issue a token and scan:' );
        WP_CLI::log( '#' );
        WP_CLI::log( '#   TOKEN=$(wp wpsec token)' );
        WP_CLI::log( '#   wpsecscan ' . get_site_url() . ' --companion-token "$TOKEN"' );
    }
}

WP_CLI::add_command( 'wpsec', 'WPSecScan_Companion_CLI' );
