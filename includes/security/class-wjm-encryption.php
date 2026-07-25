<?php
/**
 * AES-256-CBC encryption for API credentials.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Encryption {

	/**
	 * Derive a 32-byte key from WordPress salts.
	 *
	 * @return string
	 */
	private static function key() {
		$material = wp_salt( 'auth' ) . wp_salt( 'secure_auth' );
		return hash( 'sha256', $material, true );
	}

	/**
	 * Encrypt plaintext.
	 *
	 * @param string $plaintext Value to encrypt.
	 * @return string Base64 payload (iv:cipher).
	 */
	public static function encrypt( $plaintext ) {
		if ( '' === $plaintext || null === $plaintext ) {
			return '';
		}

		$iv     = random_bytes( 16 );
		$cipher = openssl_encrypt( $plaintext, 'AES-256-CBC', self::key(), OPENSSL_RAW_DATA, $iv );
		if ( false === $cipher ) {
			return '';
		}

		return base64_encode( $iv . $cipher );
	}

	/**
	 * Decrypt payload.
	 *
	 * @param string $payload Encrypted payload.
	 * @return string
	 */
	public static function decrypt( $payload ) {
		if ( '' === $payload || null === $payload ) {
			return '';
		}

		$raw = base64_decode( $payload, true );
		if ( false === $raw || strlen( $raw ) < 17 ) {
			return '';
		}

		$iv     = substr( $raw, 0, 16 );
		$cipher = substr( $raw, 16 );
		$plain  = openssl_decrypt( $cipher, 'AES-256-CBC', self::key(), OPENSSL_RAW_DATA, $iv );

		return false === $plain ? '' : $plain;
	}

	/**
	 * Store an encrypted option.
	 *
	 * @param string $option Option name.
	 * @param string $value  Plaintext.
	 */
	public static function set_secret( $option, $value ) {
		update_option( $option, self::encrypt( $value ), false );
	}

	/**
	 * Retrieve a decrypted option.
	 *
	 * @param string $option Option name.
	 * @return string
	 */
	public static function get_secret( $option ) {
		return self::decrypt( (string) get_option( $option, '' ) );
	}
}
