package org.sentrysoftware.winrm.service.client;

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

import static javax.xml.ws.handler.MessageContext.WSDL_OPERATION;

import java.util.Collections;
import java.util.Iterator;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

/**
 * Code from io.cloudsoft.winrm4j.client.StripShellResponseHandler
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
public class StripShellResponseHandler implements SOAPHandler<SOAPMessageContext> {

	@Override
	public boolean handleMessage(final SOAPMessageContext context) {

		final Boolean messageOutbound =
				(Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (messageOutbound != null && messageOutbound.booleanValue()) {
			return true;
		}

		final QName action = (QName) context.get(WSDL_OPERATION);
		if (action != null  && !"Create".equals(action.getLocalPart())) {
			return true;
		}

		final Iterator<?> childIterator = getBodyChildren(context);
		while(childIterator.hasNext()) {
			final Object node = childIterator.next();

			if (node instanceof SOAPElement) {
				final SOAPElement soapElement = (SOAPElement) node;
				if ("Shell".equals(soapElement.getLocalName())) {
					childIterator.remove();
				}
			}
		}

		return true;
	}

	private Iterator<?> getBodyChildren(final SOAPMessageContext context) {
		try {
			final SOAPEnvelope envelope = context.getMessage().getSOAPPart().getEnvelope();
			final SOAPBody body = envelope.getBody();

			return body.getChildElements();

		} catch (final SOAPException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public boolean handleFault(final SOAPMessageContext context) {
		return true;
	}

	@Override
	public void close(final MessageContext context) {
		// Do nothing
	}

	@Override
	public Set<QName> getHeaders() {
		return Collections.emptySet();
	}
}
