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

import org.apache.cxf.message.Message;

/**
 * Code from io.cloudsoft.winrm4j.client.encryption.SignAndEncryptOutInterceptor.ContentWithType
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
class ContentWithType {
	private final String contentType;
	private final byte[] payload;

	private ContentWithType(final String contentType, final byte[] payload) {
		this.contentType = contentType;
		this.payload = payload;
	}

	static ContentWithType of(final Message message, final byte[] payload) {
		return new ContentWithType((String) message.get(Message.CONTENT_TYPE), payload);
	}

	ContentWithType with(final byte[] payload) {
		return new ContentWithType(contentType, payload);
	}

	String getContentType() {
		return contentType;
	}

	byte[] getPayload() {
		return payload;
	}
}
