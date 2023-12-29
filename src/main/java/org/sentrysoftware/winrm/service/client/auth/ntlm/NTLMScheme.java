// copy of code from apache-httpclient 4.5.13 package org.apache.http.impl.auth
// changes:
// - package name, this header, imports
// - gather NTLM signing key and attach to context

/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License");
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
package org.sentrysoftware.winrm.service.client.auth.ntlm;

import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AUTH;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.InvalidCredentialsException;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.auth.NTCredentials;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.message.BufferedHeader;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.CharArrayBuffer;

import org.sentrysoftware.winrm.Utils;

/**
 * NTLM is a proprietary authentication scheme developed by Microsoft
 * and optimized for Windows platforms.
 *
 * Code from io.cloudsoft.winrm4j.client.ntlm.forks.httpclient.NTLMScheme
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 * io.cloudsoft.winrm4j.client.ntlm.forks.httpclient is a fork of apache-httpclient 4.5.13
 */
public class NTLMScheme extends AuthSchemeBase {

	private enum State {
		UNINITIATED,
		CHALLENGE_RECEIVED,
		MSG_TYPE1_GENERATED,
		MSG_TYPE2_RECEVIED,
		MSG_TYPE3_GENERATED,
		FAILED,
	}

	private final NTLMEngine engine;

	private State state;
	private String challenge;

	public NTLMScheme(final NTLMEngine engine) {
		super();
		Utils.checkNonNull(engine, "engine");
		this.engine = engine;
		state = State.UNINITIATED;
		challenge = null;
	}

	@Override
	public String getSchemeName() {
		return "ntlm";
	}

	@Override
	public String getParameter(final String name) {
		// String parameters not supported
		return null;
	}

	@Override
	public String getRealm() {
		// NTLM does not support the concept of an authentication realm
		return null;
	}

	@Override
	public boolean isConnectionBased() {
		return true;
	}

	@Override
	protected void parseChallenge(final CharArrayBuffer buffer, final int beginIndex, final int endIndex)
			throws MalformedChallengeException {
		challenge = buffer.substringTrimmed(beginIndex, endIndex);
		if (challenge.isEmpty()) {
			if (state == State.UNINITIATED) {
				state = State.CHALLENGE_RECEIVED;
			} else {
				state = State.FAILED;
			}
		} else {
			if (state.compareTo(State.MSG_TYPE1_GENERATED) < 0) {
				state = State.FAILED;
				throw new MalformedChallengeException("Out of sequence NTLM response message");
			} else if (state == State.MSG_TYPE1_GENERATED) {
				state = State.MSG_TYPE2_RECEVIED;
			}
		}
	}

	@Override
	public Header authenticate(final Credentials credentials, final HttpRequest request)
			throws AuthenticationException {
		NTCredentials ntcredentials = null;
		try {
			ntcredentials = (NTCredentials) credentials;
		} catch (final ClassCastException e) {
			throw new InvalidCredentialsException(
					"Credentials cannot be used for NTLM authentication: " + credentials.getClass().getName());
		}
		String response = null;
		if (state == State.FAILED) {
			throw new AuthenticationException("NTLM authentication failed");
		} else if (state == State.CHALLENGE_RECEIVED) {
			response = this.engine.generateType1Msg(ntcredentials.getDomain(), ntcredentials.getWorkstation());
			state = State.MSG_TYPE1_GENERATED;

			if (credentials instanceof NTCredentialsWithEncryption) {
				((NTCredentialsWithEncryption) credentials).resetEncryption(request);
			}
		} else if (state == State.MSG_TYPE2_RECEVIED) {
			final Type3Message responseO = engine.generateType3MsgObject(
					ntcredentials.getUserName(),
					ntcredentials.getPassword(),
					ntcredentials.getDomain(),
					ntcredentials.getWorkstation(),
					challenge);

			response = responseO.getResponse();
			state = State.MSG_TYPE3_GENERATED;
			if (credentials instanceof NTCredentialsWithEncryption) {
				((NTCredentialsWithEncryption) credentials).initEncryption(responseO, request);
			}
		} else {
			throw new AuthenticationException("Unexpected state: " + state);
		}
		final CharArrayBuffer buffer = new CharArrayBuffer(32);
		if (isProxy()) {
			buffer.append(AUTH.PROXY_AUTH_RESP);
		} else {
			buffer.append(AUTH.WWW_AUTH_RESP);
		}
		buffer.append(": NTLM ");
		buffer.append(response);
		return new BufferedHeader(buffer);
	}

	@Override
	public boolean isComplete() {
		return state == State.MSG_TYPE3_GENERATED || state == State.FAILED;
	}

	@Override
	public Header authenticate(final Credentials credentials, final HttpRequest request, final HttpContext context)
			throws AuthenticationException {
		return authenticate(credentials, request);
	}
}
