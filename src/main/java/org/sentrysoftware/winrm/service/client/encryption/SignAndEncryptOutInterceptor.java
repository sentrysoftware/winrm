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

import java.io.OutputStream;

import org.apache.cxf.interceptor.StaxOutInterceptor;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

/**
 * Not only encrypts if necessary, but must track the payload and make it available to
 * {@link AsyncHttpEncryptionAwareConduit} in case we need to subsequently encrypt.
 *
 * Code from io.cloudsoft.winrm4j.client.encryption.SignAndEncryptOutInterceptor.SignAndEncryptOutInterceptor
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
public class SignAndEncryptOutInterceptor extends AbstractPhaseInterceptor<Message> {

	private static final String APPLIED = SignAndEncryptOutInterceptor.class.getSimpleName() + ".APPLIED";

	public SignAndEncryptOutInterceptor() {
		super(Phase.PRE_STREAM);
		// we need to be set before various other output devices, so they write to us
		addBefore(StaxOutInterceptor.class.getName());
	}

	@Override
	public void handleMessage(final Message message) {
		boolean hasApplied = message.containsKey(APPLIED);
		if (!hasApplied) {
			message.put(APPLIED, Boolean.TRUE);
			final OutputStream outputStream = message.getContent(OutputStream.class);
			final EncryptAndSignOutputStream newOut = new EncryptAndSignOutputStream(message, outputStream);
			message.setContent(OutputStream.class, newOut);
			message.setContent(EncryptAndSignOutputStream.class, newOut);
		}
	}
}
