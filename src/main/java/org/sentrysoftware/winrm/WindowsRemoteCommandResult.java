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

public class WindowsRemoteCommandResult {

	private final String stdout;
	private final String stderr;
	private final float executionTime;
	private final int statusCode;

	/**
	 * Command Result constructor
	 *
	 * @param stdout The stdout of the command
	 * @param stderr The stderr of the command
	 * @param executionTime The execution time of the command in milliseconds
	 * @param statusCode The command return status code
	 */
	public WindowsRemoteCommandResult(
			final String stdout,
			final String stderr,
			final float executionTime,
			final int statusCode) {
		this.stdout = stdout;
		this.stderr = stderr;
		this.executionTime = executionTime;
		this.statusCode = statusCode;
	}

	/**
	 * Get the stdout of the command.
	 * @return
	 */
	public String getStdout() {
		return stdout;
	}

	/**
	 * Get the stderr of the command.
	 * @return
	 */
	public String getStderr() {
		return stderr;
	}

	/**
	 * Get the execution time of the command in seconds.
	 * @return
	 */
	public float getExecutionTime() {
		return executionTime;
	}

	/**
	 * Get the return status code of the command
	 * @return
	 */
	public int getStatusCode() {
		return statusCode;
	}

	@Override
	public String toString() {
		return new StringBuilder()
				.append("WindowsRemoteCommandResult:\nstdout:\n").append(stdout)
				.append("\nstderr:\n").append(stderr)
				.append("\nexecutionTime = ").append(executionTime)
				.append("\nstatusCode = ").append(statusCode)
				.toString();
	}
}
