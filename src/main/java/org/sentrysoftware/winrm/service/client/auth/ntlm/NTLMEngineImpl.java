// copy of code from apache-httpclient 4.5.13 package org.apache.http.impl.auth
// changes:
// - package name, this header, imports
// - fix minor errors/typos
// - allow class to be extended and flags to be customized (increase many things' visibility to protected and make class non-final)
// - expose Type3 message (public) so keys can be gathered
// - expose encryption methods
// - make flags injectable to Type1 message

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

import org.apache.http.impl.auth.NTLMEngineException;

/**
 * Provides an implementation for NTLMv1, NTLMv2, and NTLM2 Session forms of the NTLM
 * authentication protocol.
 *
 * Code from io.cloudsoft.winrm4j.client.ntlm.forks.httpclient.NTLMEngineImpl
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 * io.cloudsoft.winrm4j.client.ntlm.forks.httpclient is a fork of apache-httpclient 4.5.13
 */
class NTLMEngineImpl implements NTLMEngine {

	/** Strip dot suffix from a name */
	private static String stripDotSuffix(final String value) {
		if (value == null) {
			return null;
		}
		final int index = value.indexOf('.');
		if (index != -1) {
			return value.substring(0, index);
		}
		return value;
	}

	/** Convert host to standard form */
	static String convertHost(final String host) {
		return stripDotSuffix(host);
	}

	/** Convert domain to standard form */
	static String convertDomain(final String domain) {
		return stripDotSuffix(domain);
	}

	@Override
	public String generateType1Msg(final String domain, final String workstation) throws NTLMEngineException {
		return new Type1Message(null, null, getDefaultFlags()).getResponse();
	}

	// function overriden in NtlmMasqAsSpnegoScheme
	Integer getDefaultFlags() {
		return Type1Message.getDefaultFlags();
	}

	@Override
	public String generateType3Msg(
			final String username,
			final String password,
			final String domain,
			final String workstation,
			final String challenge) throws NTLMEngineException {
		return generateType3MsgObject(username, password, domain, workstation, challenge).getResponse();
	}

	@Override
	public Type3Message generateType3MsgObject(
			final String username,
			final String password,
			final String domain,
			final String workstation,
			final String challenge) throws NTLMEngineException {
		final Type2Message t2m = new Type2Message(challenge);
		return new Type3Message(
				domain,
				workstation,
				username,
				password,
				t2m.getChallenge(),
				t2m.getFlags(),
				t2m.getTarget(),
				t2m.getTargetInfo());
	}
}
