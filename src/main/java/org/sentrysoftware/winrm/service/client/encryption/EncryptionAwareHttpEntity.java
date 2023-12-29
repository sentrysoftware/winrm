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

import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.protocol.HTTP;

/**
 * Code from io.cloudsoft.winrm4j.client.encryption.AsyncHttpEncryptionAwareConduit.EncryptionAwareHttpEntity
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
public abstract class EncryptionAwareHttpEntity extends BasicHttpEntity {

	public void refreshHeaders(final HttpEntityEnclosingRequest request) {
		final ContentWithType appropriate = getAppropriate();
		setContentLength(appropriate.getPayload().length);

		request.setHeader(HTTP.CONTENT_LEN, String.valueOf(appropriate.getPayload().length));
		request.setHeader(HTTP.CONTENT_TYPE, appropriate.getContentType());
	}

	protected abstract ContentWithType getAppropriate();
}
