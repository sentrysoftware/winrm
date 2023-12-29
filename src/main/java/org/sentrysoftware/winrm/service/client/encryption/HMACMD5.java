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

import java.security.MessageDigest;

/**
 * Cryptography support - HMACMD5 - algorithmically based on various web
 * resources by Karl Wright
 *
 * Code from io.cloudsoft.winrm4j.client.ntlm.forks.httpclient.NTLMEngineImpl
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 * io.cloudsoft.winrm4j.client.ntlm.forks.httpclient is a fork of apache-httpclient 4.5.13
 */
public class HMACMD5 {

	private final byte[] ipad;
	private final byte[] opad;
	private final MessageDigest md5;

	HMACMD5(final byte[] input) {
		byte[] key = input;
		md5 = EncryptionUtils.getMD5();

		// Initialize the pad buffers with the key
		ipad = new byte[64];
		opad = new byte[64];

		int keyLength = key.length;
		if (keyLength > 64) {
			// Use MD5 of the key instead, as described in RFC 2104
			md5.update(key);
			key = md5.digest();
			keyLength = key.length;
		}
		int i = 0;
		while (i < keyLength) {
			ipad[i] = (byte) (key[i] ^ (byte) 0x36);
			opad[i] = (byte) (key[i] ^ (byte) 0x5c);
			i++;
		}
		while (i < 64) {
			ipad[i] = (byte) 0x36;
			opad[i] = (byte) 0x5c;
			i++;
		}

		// Very important: processChallenge the digest with the ipad buffer
		md5.reset();
		md5.update(ipad);

	}

	/** Grab the current digest. This is the "answer". */
	byte[] getOutput() {
		final byte[] digest = md5.digest();
		md5.update(opad);
		return md5.digest(digest);
	}

	/** Update by adding a complete array */
	void update(final byte[] input) {
		md5.update(input);
	}
}
