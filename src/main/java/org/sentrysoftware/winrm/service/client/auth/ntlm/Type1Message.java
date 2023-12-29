package org.sentrysoftware.winrm.service.client.auth.ntlm;

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

import java.util.Locale;

/**
 * Type 1 message assembly class
 * 
 * Code from io.cloudsoft.winrm4j.client.ntlm.forks.httpclient.NTLMEngineImpl
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 * io.cloudsoft.winrm4j.client.ntlm.forks.httpclient is a fork of apache-httpclient 4.5.13
 */
class Type1Message extends NTLMMessage {

	private final byte[] hostBytes;
	private final byte[] domainBytes;
	private final int flags;

	Type1Message(final String domain, final String host, final Integer flags) {
		super();
		this.flags = flags == null ? getDefaultFlags() : flags;

		// Strip off domain name from the host!
		final String unqualifiedHost = NTLMEngineImpl.convertHost(host);
		// Use only the base domain name!
		final String unqualifiedDomain = NTLMEngineImpl.convertDomain(domain);

		hostBytes = unqualifiedHost != null ?
				unqualifiedHost.getBytes(NTLMEngineUtils.UNICODE_LITTLE_UNMARKED) : null;
		domainBytes = unqualifiedDomain != null ?
				unqualifiedDomain
						.toUpperCase(Locale.ROOT)
						.getBytes(NTLMEngineUtils.UNICODE_LITTLE_UNMARKED) :
				null;
	}

	static int getDefaultFlags() {
		return
			// Required flags
			NTLMEngineUtils.FLAG_REQUEST_NTLM_V1 |
			NTLMEngineUtils.FLAG_REQUEST_NTLM2_SESSION |
			NTLMEngineUtils.FLAG_REQUEST_VERSION |
			NTLMEngineUtils.FLAG_REQUEST_ALWAYS_SIGN |
			NTLMEngineUtils.FLAG_REQUEST_128BIT_KEY_EXCH |
			NTLMEngineUtils.FLAG_REQUEST_56BIT_ENCRYPTION |
			NTLMEngineUtils.FLAG_REQUEST_UNICODE_ENCODING;
	}

	/**
	 * Getting the response involves building the message before returning it
	 */
	@Override
	protected void buildMessage() {
		int domainBytesLength = 0;
		if ( domainBytes != null ) {
			domainBytesLength = domainBytes.length;
		}
		int hostBytesLength = 0;
		if ( hostBytes != null ) {
			hostBytesLength = hostBytes.length;
		}

		// Now, build the message. Calculate its length first, including signature or type.
		final int finalLength = 32 + 8 + hostBytesLength + domainBytesLength;

		// Set up the response. This will initialize the signature, message, type, and flags.
		prepareResponse(finalLength, 1);

		// Flags. These are the complete set of flags we support.
		addULong(flags);

		// Domain length (two times).
		addUShort(domainBytesLength);
		addUShort(domainBytesLength);

		// Domain offset.
		addULong(hostBytesLength + 32 + 8);

		// Host length (two times).
		addUShort(hostBytesLength);
		addUShort(hostBytesLength);

		// Host offset (always 32 + 8).
		addULong(32 + 8);

		// Version
		addUShort(0x0105);
		// Build
		addULong(2600);
		// NTLM revision
		addUShort(0x0f00);

		// Host (workstation) String.
		if (hostBytes != null) {
			addBytes(hostBytes);
		}
		// Domain String.
		if (domainBytes != null) {
			addBytes(domainBytes);
		}
	}
}
