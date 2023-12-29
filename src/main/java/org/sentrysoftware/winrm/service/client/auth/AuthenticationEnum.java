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

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum AuthenticationEnum {

	NTLM,
	KERBEROS;

	private static final Map<String, AuthenticationEnum> VALUES_OF =
			Stream.of(values()).collect(Collectors.toMap(AuthenticationEnum::name, Function.identity()));

	/**
	 * Get the value of the enum Name regardless the cardinality.
	 *
	 * @param name The enum value name
	 * 
	 * @return An optional with the enum value if found empty otherwise
	 */
	public static Optional<AuthenticationEnum> getValueOf(final String name) {
		return name != null ? Optional.ofNullable(VALUES_OF.get(name.trim().toUpperCase())) : Optional.empty();
	}
}
