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

import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.binding.soap.interceptor.SoapPreProtocolOutInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.jaxb.JAXBDataBinding;
import org.apache.cxf.phase.Phase;

import org.sentrysoftware.winrm.Utils;
import com.sentrysoftware.matsya.winrm.service.wsman.AttributableURI;
import com.sentrysoftware.matsya.winrm.service.wsman.ObjectFactory;

/**
 * Code from org.opennms.core.wsman.cxf.WSManHeaderInterceptor
 * release 1.2.3 @link https://github.com/OpenNMS/wsman
 */
public class WSManHeaderInterceptor extends AbstractSoapInterceptor {

	private static final JAXBDataBinding ATTRIBUTABLE_URI_JAXB_DATA_BINDING;
	static {
		try {
			ATTRIBUTABLE_URI_JAXB_DATA_BINDING = new JAXBDataBinding(AttributableURI.class);
		} catch (final JAXBException e) {
			throw new RuntimeException(
					"Failed to create JAXBDataBinding for: AttributableURI" + AttributableURI.class,
					e);
		}
	}

	private final String resourceUri;

	public WSManHeaderInterceptor(final String resourceUri) {
		super(Phase.POST_LOGICAL);

		addAfter(SoapPreProtocolOutInterceptor.class.getName());

		Utils.checkNonNull(resourceUri, "resourceUri");

		this.resourceUri = resourceUri;
	}

	@Override
	public void handleMessage(final SoapMessage message) throws Fault {

		final JAXBElement<String> resourceURI = new ObjectFactory().createResourceURI(resourceUri);

		final List<Header> headers = message.getHeaders();
		headers.add(
				new Header(resourceURI.getName(), resourceURI, ATTRIBUTABLE_URI_JAXB_DATA_BINDING));

		message.put(Header.HEADER_LIST, headers);
	}

}
