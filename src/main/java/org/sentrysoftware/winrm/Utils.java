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

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Utils {
	
	public static final String EMPTY = "";
	public static final String NEW_LINE = "\n";
	
	/**
	 * Check if the required argument is not null.
	 *
	 * @param argument
	 * @param name
	 * @throws IllegalArgumentException if the argument is null
	 */
	public static <T> void checkNonNull(final T argument, final String name) {
		if (argument == null) {
			throw new IllegalArgumentException(name + " must not be null.");
		}
	}
	
	/**
	 * @param value The value to check
	 * @return whether the value is null, empty or contains only blank chars
	 */
	public static boolean isBlank(String value) {
		return value == null || isEmpty(value);
	}
	
	/**
	 * @param value The value to check
	 * @return whether the value is empty of non-blank chars
	 * @throws NullPointerException if value is <em>null</em>
	 */
	public static boolean isEmpty(String value) {
		return value.trim().isEmpty();
	}
	
	/**
	 * @param value The value to check
	 * @return whether the value is not null, nor empty nor contains only blank chars
	 */
	public static boolean isNotBlank(final String value) {
		return !isBlank(value);
	}
	
	/**
	 * @return the name of the local computer (or "localhost" if it can't be determined)
	 */
	public static String getComputerName() {
		final String computerName = System.getenv("COMPUTERNAME");
		if (computerName == null) {
			return "localhost";
		}
		return computerName;
	}
	
	/**
	 * Wrapper for Thread.sleep(millis)
	 * 
	 * @param millis Time to sleep (in milliseconds)
	 * @throws InterruptedException
	 */
	public static void sleep(final long millis) throws InterruptedException {
		Thread.sleep(millis);
	}
	
	/**
	 * Check if the required argument is not negative or zero.
	 *
	 * @param argument
	 * @param name
	 * @throws IllegalArgumentException if the argument is null
	 */
	public static void checkArgumentNotZeroOrNegative(final long argument, final String name) {
		if (argument <= 0) {
			throw new IllegalArgumentException(String.format("%s=%d must not be negative or zero.", name, argument));
		}
	}
	
	/**
	 * Get the current time in Milliseconds.
	 * @return the current time in Milliseconds.
	 */
	public static long getCurrentTimeMillis() {
		return System.currentTimeMillis();
	}
	
	/**
	 * Check if the required argument is not blank (null or empty).
	 *
	 * @param argument
	 * @param name
	 * @throws IllegalArgumentException if the argument is null
	 */
	public static <T> void checkNonBlank(final String argument, final String name) {
		if (isBlank(argument)) {
			throw new IllegalArgumentException(name + " must not be null or empty.");
		}
	}
	
	/**
	 * Run the given {@link Callable} using the passed timeout in seconds.
	 *
	 * @param <T>
	 * @param callable
	 * @param timeout
	 * @return {@link T} result returned by the callable
	 *
	 * @throws InterruptedException
	 * @throws ExecutionException
	 * @throws TimeoutException
	 */
	public static <T> T execute(Callable<T> callable, long timeout)
			throws InterruptedException, ExecutionException, TimeoutException {

		ExecutorService executorService = Executors.newSingleThreadExecutor();
		Future<T> future = executorService.submit(callable);

		try {
			return future.get(timeout, TimeUnit.MILLISECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw e;
		} catch (TimeoutException e) {
			future.cancel(true);
			throw e;
		} finally {
			executorService.shutdownNow();
		}
	}
	
	/**
	 * Check if the required field is not null.
	 *
	 * @param field
	 * @param name
	 * @throws IllegalStateException if the argument is null
	 */
	public static <T> void checkNonNullField(final T field, final String name) {
		if (field == null) {
			throw new IllegalStateException(name + " must not be null.");
		}
	}

}
