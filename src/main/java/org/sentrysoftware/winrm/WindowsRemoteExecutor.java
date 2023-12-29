package org.sentrysoftware.winrm;

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

import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import org.sentrysoftware.winrm.exceptions.WindowsRemoteException;
import org.sentrysoftware.winrm.exceptions.WqlQuerySyntaxException;

public interface WindowsRemoteExecutor extends AutoCloseable {

	/**
	 * <p>Execute a WQL query and process its result.</p>
	 *
	 * @param wqlQuery the WQL query (required)
	 * @param timeout Timeout in milliseconds (throws an IllegalArgumentException if negative or zero)
	 * 
	 * @return a list of result rows. A result row is a Map(LinkedHashMap to preserve the query order) of
	 * properties/values.
	 * 
	 * @throws TimeoutException to notify userName of timeout.
	 * @throws WqlQuerySyntaxException if WQL query syntax is invalid
	 * @throws WindowsRemoteException For any problem encountered
	 */
	public List<Map<String, Object>> executeWql(
			final String wqlQuery,
			final long timeout) throws TimeoutException, WqlQuerySyntaxException, WindowsRemoteException;

	/**
	 * Execute the command on the remote
	 * 
	 * @param command The command to execute
	 * @param workingDirectory Path of the directory for the spawned process on the remote system (can be null)
	 * @param charset The charset
	 * @param timeout Timeout in milliseconds
	 * 
	 * @return The command result
	 * 
	 * @throws WindowsRemoteException For any problem encountered
	 * @throws TimeoutException To notify userName of timeout.
	 */
	public WindowsRemoteCommandResult executeCommand(
			final String command,
			final String workingDirectory,
			final Charset charset,
			final long timeout
			) throws WindowsRemoteException, TimeoutException;

	/**
	 * Get the hostname.
	 * @return
	 */
	public String getHostname();

	/**
	 * Get the username.
	 * @return
	 */
	public String getUsername();

	/**
	 * Get the password.
	 * @return
	 */
	public char[] getPassword();
}
