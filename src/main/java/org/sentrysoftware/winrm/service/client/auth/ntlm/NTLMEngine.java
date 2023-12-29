// copy of code from apache-httpclient 4.5.13 package org.apache.http.impl.auth
// changes:
// - package name, this header, imports
// - expose Type3 message (package-private) so keys can be gathered

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
 * Abstract NTLM authentication engine. The engine can be used to
 * generate Type1 messages and Type3 messages in response to a Type2 challenge.
 * 
 * Code from io.cloudsoft.winrm4j.client.ntlm.forks.httpclient.NTLMEngine
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 * io.cloudsoft.winrm4j.client.ntlm.forks.httpclient is a fork of apache-httpclient 4.5.13
 */
public interface NTLMEngine {

	/**
	 * Generates a Type1 message given the domain and workstation.
	 *
	 * @param domain Optional Windows domain name. Can be {@code null}.
	 * @param workstation Optional Windows workstation name. Can be
	 *  {@code null}.
	 * @return Type1 message
	 * @throws NTLMEngineException
	 */
	String generateType1Msg(final String domain, final String workstation) throws NTLMEngineException;

	/**
	 * Generates a Type3 message given the user credentials and the
	 * authentication challenge.
	 *
	 * @param username Windows user name
	 * @param password Password
	 * @param domain Windows domain name
	 * @param workstation Windows workstation name
	 * @param challenge Type2 challenge.
	 * @return Type3 response.
	 * @throws NTLMEngineException
	 */
	String generateType3Msg(
			final String username,
			final String password,
			final String domain,
			final String workstation,
			final String challenge) throws NTLMEngineException;

	Type3Message generateType3MsgObject(
			final String username,
			final String password,
			final String domain,
			final String workstation,
			final String challenge) throws NTLMEngineException;

}
