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

import java.util.function.LongUnaryOperator;

import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.message.BasicHeader;

/**
 * Code from io.cloudsoft.winrm4j.client.ntlm.NtlmMasqAsSpnegoScheme
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
public class NtlmMasqAsSpnegoScheme extends NTLMScheme {

	private static final LongUnaryOperator FLAG_MODIFIER =
			flags -> flags |
						NTLMEngineUtils.NTLMSSP_NEGOTIATE_SIGN |
						NTLMEngineUtils.NTLMSSP_NEGOTIATE_SEAL |
						NTLMEngineUtils.NTLMSSP_NEGOTIATE_KEY_EXCH;

	public NtlmMasqAsSpnegoScheme() {
		super(newDefaultNtlmEngine());
	}
	private static NTLMEngine newDefaultNtlmEngine() {
		return new NTLMEngineImpl() {
			@Override
			public Integer getDefaultFlags() {
				final Long flags = (long) Type1Message.getDefaultFlags();
				return (int) FLAG_MODIFIER.applyAsLong(flags);
			}
		};
	}

	@Override
	public String getSchemeName() {
		return AuthSchemes.SPNEGO;
	}

	@Override
	public Header authenticate(final Credentials credentials, final HttpRequest httpRequest)
			throws AuthenticationException {
		final Header header = super.authenticate(credentials, httpRequest);

		// code from winrm4j implementation: https://github.com/cloudsoft/winrm4j
		return new BasicHeader(header.getName(), header.getValue().replace("NTLM", getSchemeName()));
	}
}
