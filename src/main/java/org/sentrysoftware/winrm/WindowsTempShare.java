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

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import org.sentrysoftware.winrm.exceptions.WindowsRemoteException;
import org.sentrysoftware.winrm.exceptions.WqlQuerySyntaxException;

public class WindowsTempShare {

	/** The share name */
	private final String shareName;

	/** The UNC path of the share. */
	private final String uncSharePath;

	/** The remote path.*/
	private final String remotePath;

	/** The WindowsRemoteExecutor instance */
	private final WindowsRemoteExecutor windowsRemoteExecutor;

	/**
	 * Constructor of WindowsTempShare
	 * 
	 * @param windowsRemoteExecutor the WindowsRemoteExecutor instance
	 * connected to the remote host (mandatory)
	 * @param shareNameOrUnc The name of the share, or its full UNC path (mandatory)
	 * @param remotePath The path on the remote system of the directory being shared
	 */
	public WindowsTempShare(
			final WindowsRemoteExecutor windowsRemoteExecutor,
			final String shareNameOrUnc,
			final String remotePath) {

		Utils.checkNonNull(windowsRemoteExecutor, "windowsRemoteExecutor");
		Utils.checkNonNull(shareNameOrUnc, "shareNameOrUnc");

		if (shareNameOrUnc.startsWith("\\\\")) {
			this.uncSharePath = shareNameOrUnc;
			final String[] uncElements = shareNameOrUnc.split("\\\\");
			this.shareName = uncElements[3];
		} else {
			this.uncSharePath = buildUncPath(windowsRemoteExecutor.getHostname(), shareNameOrUnc);
			this.shareName = shareNameOrUnc;
		}

		this.remotePath = remotePath;
		this.windowsRemoteExecutor = windowsRemoteExecutor;
	}

	/**
	 * Get the existing share on the host or create it if absent.
	 *
	 * @param windowsRemoteExecutor WindowsRemoteExecutor instance. (mandatory)
	 * @param timeout Timeout in milliseconds. (throws an IllegalArgumentException if negative or zero)
	 * @param shareRemoteDirectory ShareRemoteDirectoryConsumer function (mandatory)
	 * 
	 * @return The remote path.
	 * 
	 * @throws TimeoutException To notify userName of timeout.
	 * @throws WindowsRemoteException For any problem encountered.
	 */
	public static WindowsTempShare getOrCreateShare(
			final WindowsRemoteExecutor windowsRemoteExecutor,
			final long timeout,
			final ShareRemoteDirectoryConsumer<WindowsRemoteExecutor, String, String, Long> shareRemoteDirectory)
					throws TimeoutException, WindowsRemoteException {

		Utils.checkNonNull(windowsRemoteExecutor, "windowsRemoteExecutor");
		Utils.checkArgumentNotZeroOrNegative(timeout, "timeout");
		Utils.checkNonNull(shareRemoteDirectory, "shareRemoteDirectory");

		final long start = Utils.getCurrentTimeMillis();

		// Are we targeting a Windows cluster?
		// (in which case, things are a bit different)

		// Try to get a clustered share
		final Optional<WindowsTempShare> clusterShare = getClusterShare(
				windowsRemoteExecutor,
				TimeoutHelper.getRemainingTime(timeout, start, "No time left to check for cluster share"),
				start);

		if (clusterShare.isPresent()) {
			return clusterShare.get();
		}

		// Normal case (non-cluster)
		final String shareName = buildShareName();
		final Optional<WindowsTempShare> share = getShare(
				windowsRemoteExecutor,
				shareName,
				TimeoutHelper.getRemainingTime(timeout, start, "No time left to get a normal temporary share"));
		if (share.isPresent()) {
			return share.get();
		}

		return createTempShare(
				windowsRemoteExecutor,
				shareName,
				TimeoutHelper.getRemainingTime(timeout, start, "No time left to create the temporary share"),
				shareRemoteDirectory);
	}

	/**
	 * Get the Windows directory.
	 *
	 * @param windowsRemoteExecutor WindowsRemoteExecutor instance. (mandatory)
	 * @param timeout Timeout in milliseconds. (throws an IllegalArgumentException if negative or zero)
	 * 
	 * @return The Windows directory.
	 * 
	 * @throws WindowsRemoteException For any problem encountered.
	 * @throws TimeoutException To notify userName of timeout.
	 * 
	 * @see <a href="https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem">
	 * Win32_OperatingSystem class</a>
	 *
	 */
	public static String getWindowsDirectory(
			final WindowsRemoteExecutor windowsRemoteExecutor,
			final long timeout) throws WindowsRemoteException, TimeoutException {

		Utils.checkNonNull(windowsRemoteExecutor, "windowsRemoteExecutor");
		Utils.checkArgumentNotZeroOrNegative(timeout, "timeout");

		try {
			// Extract the WindowsDirectory property from the first instance and return it (or throw an exception)
			return windowsRemoteExecutor.executeWql(
					"SELECT WindowsDirectory FROM Win32_OperatingSystem",
					timeout
					).stream()
					.limit(1)
					.map(row -> (String) row.get("WindowsDirectory"))
					.filter(Objects::nonNull)
					.findFirst()
					.orElseThrow(
							() -> new WindowsRemoteException(
									String.format("Couldn't identify the Windows root directory on %s.",
											windowsRemoteExecutor.getHostname())));

		} catch (final WqlQuerySyntaxException e) {
			throw new WindowsRemoteException(e); // Impossible
		}
	}

	/**
	 * Create the remote directory.
	 *
	 * @param windowsRemoteExecutor WindowsRemoteExecutor instance. (mandatory)
	 * @param remotePath The remote path to create
	 * @param timeout Timeout in milliseconds
	 * @param start start time in milliseconds.
	 * 
	 * @throws WindowsRemoteException For any problem encountered.
	 * @throws TimeoutException To notify userName of timeout.
	 */
	public static void createRemoteDirectory(
			final WindowsRemoteExecutor windowsRemoteExecutor,
			final String remotePath,
			final long timeout,
			final long start) throws WindowsRemoteException, TimeoutException {

		Utils.checkNonNull(windowsRemoteExecutor, "windowsRemoteExecutor");

		windowsRemoteExecutor.executeCommand(
				buildCreateRemoteDirectoryCommand(remotePath),
				null,
				null,
				timeout);
	}

	/**
	 * Build a UNC path from hostname and share name.
	 * 
	 * Note: This method ensures compatibility with IPv6 hosts
	 * 
	 * @param hostname Host to connect to. (mandatory)
	 * @param share The share
	 * 
	 * @return The UNC path to the share (\\unc(host)\share)
	 */
	static String buildUncPath(final String hostname, final String share) {
		Utils.checkNonNull(hostname, "hostname");

		return hostname.contains(":") ?
				String.format("\\\\%s.ipv6-literal.net\\%s", hostname.replace(":", "-").replace("%", "s"), share) :
					String.format("\\\\%s\\%s", hostname, share);
	}

	/**
	 * Create the Windows command for a directory creation.
	 * 
	 * @param remotePath The remote path to create. (mandatory)
	 * 
	 * @return The command to execute.
	 */
	static String buildCreateRemoteDirectoryCommand(final String remotePath) {
		Utils.checkNonBlank(remotePath, "remotePath");

		return String.format("CMD.EXE /C IF NOT EXIST \"%s\" MKDIR %s", remotePath, remotePath);
	}

	/**
	 * @param path Root path of the temporary directory that will be used in a cluster. (mandatory)
	 * 
	 * @return Path to the temporary directory
	 */
	static String buildPathOnCluster(final String path) {
		Utils.checkNonNull(path, "path");

		return String.format("%s\\Temp\\SEN_TempFor_%s", path, Utils.getComputerName());
	}

	/**
	 * Build the remote temp path name with the folder name.
	 * 
	 * @param folder The folder name. (mandatory)
	 * @param shareName The Share Name. (mandatory)
	 * 
	 * @return The remote directory path. (folder\Temp\shareName)
	 */
	static String buildRemotePath(
			final String folder,
			final String shareName) {
		Utils.checkNonNull(folder, "folder");
		Utils.checkNonBlank(shareName, "shareName");

		return String.format("%s\\Temp\\%s", folder, shareName);
	}

	/**
	 * Build the Share name with the computer name.
	 * 
	 * @return The share name.
	 */
	static String buildShareName() {
		return String.format("SEN_ShareFor_%s$", Utils.getComputerName());
	}

	/**
	 * Retrieve an "Admin Share" (like D$, E$, etc.) that is exposed by a cluster.
	 * 
	 * If the targeted system is not a cluster, returns an empty optional.
	 * 
	 * @param windowsRemoteExecutor WindowsRemoteExecutor instance.
	 * @param timeout Timeout in milliseconds.
	 * @param start start time in milliseconds.
	 * 
	 * @return An optional Map<String, Object> with 2 entries: "Name" and "Path"
	 * 
	 * @throws TimeoutException To notify userName of timeout.
	 * @throws WindowsRemoteException For any problem encountered.
	 */
	static Optional<WindowsTempShare> getClusterShare(
			final WindowsRemoteExecutor windowsRemoteExecutor,
			final long timeout,
			final long start) throws TimeoutException, WindowsRemoteException {

		try {
			final Optional<WindowsTempShare> clusterShare = windowsRemoteExecutor.executeWql(
					"SELECT Name,Path FROM Win32_ClusterShare WHERE "
					+ "ServerName <> '*' AND (Type = 2147483648 OR Type = 3221225472) AND Name LIKE '%\\\\_$'",
					timeout
					).stream()
					.limit(1)
					.map(
							// We return a TempShare instance pointing to a subdirectory in this share
							row -> new WindowsTempShare(
									windowsRemoteExecutor,
									buildPathOnCluster((String) row.get("Name")),
									buildPathOnCluster((String) row.get("Path"))))
					.findFirst();

			if (clusterShare.isPresent()) {
				// We create the subdirectory (if necessary)
				createRemoteDirectory(windowsRemoteExecutor, clusterShare.get().getRemotePath(), timeout, start);
			}

			return clusterShare;

		} catch (final WqlQuerySyntaxException e) {
			throw new WindowsRemoteException(e); // Impossible
		}
	}

	/**
	 * Retrieve the specified share.
	 *
	 * @param windowsRemoteExecutor WindowsRemoteExecutor instance
	 * @param shareName The share name
	 * @param timeout Timeout in milliseconds
	 * 
	 * @return An optional TempShare instance
	 * 
	 * @throws TimeoutException To notify userName of timeout
	 * @throws WindowsRemoteException For any problem encountered
	 */
	static Optional<WindowsTempShare> getShare(
			final WindowsRemoteExecutor windowsRemoteExecutor,
			final String shareName,
			final long timeout
			) throws TimeoutException, WindowsRemoteException {
		try {

			return windowsRemoteExecutor.executeWql(
					String.format("SELECT Name,Path FROM Win32_Share WHERE Name = '%s'", shareName),
					timeout
					).stream()
					.limit(1)
					.map(row -> new WindowsTempShare(
							windowsRemoteExecutor,
							(String) row.get("Name"),
							(String) row.get("Path")))
					.findFirst();

		} catch (final WqlQuerySyntaxException e) {
			throw new WindowsRemoteException(e); // Impossible
		}
	}

	/**
	 * Create a shared temporary folder on the remote
	 *
	 * @param windowsRemoteExecutor WindowsRemoteExecutor instance.
	 * @param shareName The Share Name.
	 * @param timeout Timeout in milliseconds.
	 * @param shareRemoteDirectory shareRemoteDirectory function
	 * 
	 * @return A TempShare instance
	 * 
	 * @throws WindowsRemoteException For any problem encountered.
	 * @throws TimeoutException To notify userName of timeout.
	 */
	static WindowsTempShare createTempShare(
			final WindowsRemoteExecutor windowsRemoteExecutor,
			final String shareName,
			final long timeout,
			final ShareRemoteDirectoryConsumer<WindowsRemoteExecutor, String, String, Long> shareRemoteDirectory
			) throws WindowsRemoteException, TimeoutException {

		final long start = Utils.getCurrentTimeMillis();

		// Find where Windows is installed on the remote system. We will create the share under %WINDIR%\Temp.
		final String folder = getWindowsDirectory(windowsRemoteExecutor, timeout);

		// Create the folder on the remote system
		final String remotePath = buildRemotePath(folder, shareName);
		createRemoteDirectory(
				windowsRemoteExecutor,
				remotePath,
				TimeoutHelper.getRemainingTime(timeout, start, "No time left to create the temporary directory"),
				start);

		// Create the share
		shareRemoteDirectory.apply(windowsRemoteExecutor, remotePath, shareName, timeout);

		return new WindowsTempShare(windowsRemoteExecutor, shareName, remotePath);
	}

	/** Get the share name */
	public String getShareName() {
		return shareName;
	}

	/** Get the UNC path of the share */
	public String getUncSharePath() {
		return uncSharePath;
	}

	/** Get the remote path */
	public String getRemotePath() {
		return remotePath;
	}

	/** Get the WindowsRemoteExecutor instance */
	public WindowsRemoteExecutor getWindowsRemoteExecutor() {
		return windowsRemoteExecutor;
	}
}
