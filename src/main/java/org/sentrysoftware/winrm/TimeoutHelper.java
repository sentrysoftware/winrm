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

import java.util.concurrent.TimeoutException;

/**
 * for stagged timeout handling.
 *
 */
public class TimeoutHelper {

	private TimeoutHelper() { }

	/**
	 * Get the remaining time before timeout.
	 *
	 * @param timeout Timeout in milliseconds. (throws an IllegalArgumentException if negative or zero)
	 * @param start start time in milliseconds. (throws an IllegalArgumentException if negative or zero)
	 * @return The remaining time
	 * @throws TimeoutException if there's no time left
	 */
	public static long getRemainingTime(final long timeout, final long start, final String message) throws TimeoutException {
		long remaining = start + timeout - Utils.getCurrentTimeMillis();
		if (remaining < 0) {
			throw new TimeoutException(message);
		}
		return remaining;
	}

	/**
	 * Sub to make the thread sleep in a stepped delay.
	 * <p>Delay:
	 * <ul>
	 * <li>50 milliseconds for time from start &lt; 500 milliseconds</li>
	 * <li>100 milliseconds for time from start between 500 milliseconds and 1 second</li>
	 * <li>250 milliseconds for time from start between 1 second and 5 seconds</li>
	 * <li>500 milliseconds for time from start between 5 seconds and 10 seconds</li>
	 * <li>1 second for time from start between 10 seconds and 30 seconds</li>
	 * <li>3 seconds otherwise</li>
	 * </ul>
	 *
	 * @param timeout Timeout in milliseconds
	 * @param start start time in milliseconds
	 * @param message The timeout error message
	 *
	 * @throws TimeoutException when times out
	 * 
	 */
	public static void stagedSleep(
			final long timeout,
			final long start,
			final String message
	) throws TimeoutException {

		// Check we still have some time on our hands
		getRemainingTime(timeout, start, message);

		final long elapsedTime = Utils.getCurrentTimeMillis() - start;
		try {
			if (elapsedTime < 500) {
				Utils.sleep(50);
			} else if (elapsedTime < 1000) {
				Utils.sleep(100);
			} else if (elapsedTime < 5000) {
				Utils.sleep(250);
			} else if (elapsedTime < 10000) {
				Utils.sleep(500);
			} else if (elapsedTime < 30000) {
				Utils.sleep(1000);
			} else {
				Utils.sleep(3000);
			}
		} catch (InterruptedException e) {
			throw new TimeoutException(message);
		}

	}

}
