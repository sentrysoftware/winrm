package org.sentrysoftware.winrm.service;

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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Objects;

import org.sentrysoftware.winrm.HttpProtocolEnum;
import org.sentrysoftware.winrm.Utils;
import org.sentrysoftware.winrm.WmiHelper;

public class WinRMEndpoint {

	private static final int DEFAULT_WIN_RM_HTTP_PORT = 5985;
	private static final int DEFAULT_WIN_RM_HTTPS_PORT = 5986;

	private final String hostname;
	private final String endpoint;
	private final String domain;
	private final String username;
	private final char[] password;
	private final String namespace;
	private final String rawUsername;
	private final HttpProtocolEnum protocol;

	/**
	 * Constructor of the endpoint and credentials for WinRM.
	 *
	 * @param protocol The protocol
	 * @param hostname The host name (mandatory)
	 * @param port The port
	 * @param username The user name (mandatory)
	 * @param password The password (mandatory)
	 * @param namespace The namespace default value: {@value WmiHelper#DEFAULT_NAMESPACE}
	 */
	public WinRMEndpoint(
			final HttpProtocolEnum protocol,
			final String hostname,
			final Integer port,
			final String username,
			final char[] password,
			final String namespace) {

		Utils.checkNonNull(hostname, "hostname");
		Utils.checkNonNull(username, "username");
		Utils.checkNonNull(password, "password");

		this.hostname = hostname.replaceAll("\\s", Utils.EMPTY);
		this.password = password;
		rawUsername = username;

		this.namespace = buildNamespace(namespace);

		final String user = username.replaceAll("\\s", Utils.EMPTY);
		if (user.contains("\\")) {
			final String[] array = user.split("\\\\");
			domain = array[0];
			this.username = array[1];
		} else {
			domain = null;
			this.username = user;
		}

		this.protocol = protocol != null ? protocol : HttpProtocolEnum.HTTP;
		final String endpointUrl = buildEndpointUrl(this.protocol, this.hostname, port);

		endpoint = buildWSManEndpoint(endpointUrl);
	}

	/** Get the hostname */
	public String getHostname() {
		return hostname;
	}

	/** Get the endpoint in the form of http(s)://host:port/wsman */
	public String getEndpoint() {
		return endpoint;
	}

	/** Get the domain from the raw username */
	public String getDomain() {
		return domain;
	}

	/** get the username as indicated in the constructor (could be in domain\\user form) */
	public String getRawUsername() {
		return rawUsername;
	}

	/** Get the username part of the raw username */
	public String getUsername() {
		return username;
	}

	/** Get the password */
	public char[] getPassword() {
		return password;
	}

	/** Get the namespace */
	public String getNamespace() {
		return namespace;
	}

	/** Get the protocol */
	public HttpProtocolEnum getProtocol() {
		return protocol;
	}

	/**
	 * Build the endpoint URL.
	 *
	 * @param protocol The HTTP protocol
	 * @param hostname The host name
	 * @param port The port
	 * 
	 * @return the endpoint URL in form of protocol://hostname:port (with protocol in HTTP or HTTPS).
	 */
	public static String buildEndpointUrl(final HttpProtocolEnum protocol, final String hostname, final Integer port) {

		final int endpointPort = getEndpointPort(protocol, port);

		return String.format("%s://%s:%d", protocol.toString(), hostname, endpointPort);
	}

	/**
	 *	Get the endpoint port:
	 *<ul>
	 * <li>The port if provided</li>
	 * <li>5986 if the protocol is HTTPS</li>
	 * <li>5985 otherwise</li>
	 *</ul>
	 * @param protocol The HTTP protocol
	 * @param port The port
	 * 
	 * @return The endpoint port
	 */
	public static int getEndpointPort(final HttpProtocolEnum protocol, final Integer port) {
		if (port != null) {
			return port;
		}
		return protocol == HttpProtocolEnum.HTTPS ?
				DEFAULT_WIN_RM_HTTPS_PORT :
					DEFAULT_WIN_RM_HTTP_PORT;
	}

	/**
	 * Get the namespace and replace '\' by '/' if necessary
	 * default: {@value WmiHelper#DEFAULT_NAMESPACE} if null
	 * @param namespace the provided namespace
	 * 
	 * @return
	 */
	public static String buildNamespace(final String namespace) {

		final String cleanNamespace = namespace != null ?
				namespace.replaceAll("\\s", Utils.EMPTY) :
				Utils.EMPTY;

		final String usedNamespace = Utils.isNotBlank(cleanNamespace) ?
				cleanNamespace :
				WmiHelper.DEFAULT_NAMESPACE;

		return usedNamespace.replace('\\', '/');
	}

	/**
	 * Build the WSMan URL endpoint.
	 *
	 * @param endpoint the endpoint in form of protocol://hostname:port (with protocol in HTTP or HTTPS).
	 * 
	 * @return The external form of the endpoint URL
	 */
	private static String buildWSManEndpoint(final String endpoint) {
		try {
			return new URL(String.format("%s/wsman", endpoint)).toExternalForm();

		} catch (final MalformedURLException e) {
			throw new IllegalArgumentException(String.format("endpoint %s is invalid.", endpoint), e);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(password);
		result = prime * result + Objects.hash(endpoint, namespace, rawUsername);
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof WinRMEndpoint)) {
			return false;
		}
		final WinRMEndpoint other = (WinRMEndpoint) obj;
		return Objects.equals(endpoint, other.endpoint) && Objects.equals(namespace, other.namespace)
				&& Arrays.equals(password, other.password) && Objects.equals(rawUsername, other.rawUsername);
	}

	@Override
	public String toString() {
		return new StringBuilder()
				.append("WinRMEndpoint [")
				.append("endpoint=").append(endpoint)
				.append(", domain=").append(domain)
				.append(", username=").append(username)
				.append(", namespace=").append(namespace)
				.append("]")
				.toString();
	}
}
