package org.sentrysoftware.winrm.service.client.encryption;

/*-
 * ╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲
 * WinRM Java Client
 * ჻჻჻჻჻჻
 * Copyright (C) 2023 Sentry Software
 * ჻჻჻჻჻჻
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 *
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * ╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱
 */

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Code from io.cloudsoft.winrm4j.client.encryption.WinrmEncryptionUtils
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
public class EncryptionUtils {

	private EncryptionUtils() { }

	private static final String HMAC_MD5 = "HmacMD5";
	private static final String RC4 = "RC4";

	public static MessageDigest getMD5() {
		try {
			return MessageDigest.getInstance("MD5");
		} catch (final NoSuchAlgorithmException ex) {
			throw new IllegalStateException("MD5 message digest doesn't seem to exist - fatal error: "+ex.getMessage(), ex);
		}
	}

	public static byte[] md5digest(byte[] bytes) {
		final MessageDigest handle = getMD5();
		handle.update(bytes);
		return handle.digest();
	}

	public static Cipher arc4(byte[] key) {
		// engine needs to be stateful
		try {
			final Cipher rc4 = Cipher.getInstance(RC4);
			rc4.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, RC4));
			return rc4;

		} catch (final Exception e) {
			throw new IllegalStateException(e);
		}
	}

	/** Calculates RC4 */
	public static byte[] calculateRC4(final byte[] value, final byte[] key) {
		try {
			return arc4(key).doFinal(value);

		} catch (final Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static byte[] hmacMd5(byte[] key, byte[] body) {
		try {
			final SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_MD5);
			final Mac mac = Mac.getInstance(HMAC_MD5);
			mac.init(keySpec);
			return mac.doFinal( body );

		} catch (final NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalStateException(e);
		}
	}
}
