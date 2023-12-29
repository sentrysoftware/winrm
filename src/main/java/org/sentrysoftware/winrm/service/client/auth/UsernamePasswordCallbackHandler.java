package org.sentrysoftware.winrm.service.client.auth;

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

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class UsernamePasswordCallbackHandler implements CallbackHandler {

	private final String username;
	private final char[] password;

	/**
	 * UsernamePasswordCallbackHandler constructor
	 *
	 * @param username name of the user to authenticate
	 * @param password The password
	 */
	public UsernamePasswordCallbackHandler(final String username, final char[] password) {
		this.username = username;
		this.password = password;
	}

	@Override
	public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {

		if (callbacks == null) {
			return;
		}

		for (final Callback callback : callbacks) {
			if (callback instanceof NameCallback) {
				final NameCallback nameCallback = (NameCallback) callback;
				nameCallback.setName(username);

			} else if (callback instanceof PasswordCallback) {
				final PasswordCallback passwordCallback = (PasswordCallback) callback;
				passwordCallback.setPassword(password);

			} else {
				throw new UnsupportedCallbackException(callback, "Unknown Callback");
			}
		}
	}

}
