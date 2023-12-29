package org.sentrysoftware.winrm.service.client.encryption;

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
import java.io.OutputStream;

/**
 *  This OutputStream writes all data to the famous <b>/dev/null</b>.
 *  
 *  This output stream has no destination (file/socket etc.) and all
 *  bytes written to it are ignored and lost.
 *  
 *
 * PS: from common-io/NullOutputStream. Embedded to avoid to include common-io. 2.11.0
 */
class NullOutputStream extends OutputStream {

	private NullOutputStream() { }

	/**
	 * A singleton.
	 */
	static final NullOutputStream NULL_OUTPUT_STREAM = new NullOutputStream();

	/**
	 * Does nothing - output to <code>/dev/null</code>.
	 * @param b The bytes to write
	 * @param off The start offset
	 * @param len The number of bytes to write
	 */
	@Override
	public void write(final byte[] b, final int off, final int len) {
		//to /dev/null
	}

	/**
	 * Does nothing - output to <code>/dev/null</code>.
	 * @param b The byte to write
	 */
	@Override
	public void write(final int b) {
		//to /dev/null
	}

	/**
	 * Does nothing - output to <code>/dev/null</code>.
	 * @param b The bytes to write
	 * @throws IOException never
	 */
	@Override
	public void write(final byte[] b) throws IOException {
		//to /dev/null
	}
}
