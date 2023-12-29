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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

import org.apache.cxf.Bus;
import org.apache.cxf.io.CacheAndWriteOutputStream;
import org.apache.cxf.message.Message;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.transport.http.Address;
import org.apache.cxf.transport.http.asyncclient.AsyncHTTPConduit;
import org.apache.cxf.transport.http.asyncclient.CXFHttpRequest;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.apache.cxf.ws.addressing.EndpointReferenceType;
import org.apache.http.auth.Credentials;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.entity.BasicHttpEntity;

/**
 * Creates an output stream which sends back the appropriate encrypted or unencrypted stream,
 * based on the {SignAndEncryptOutInterceptor} -- which normally does the right thing,
 * but during auth events it will "guess" wrongly, and we have to change the payload and
 * the headers. {io.cloudsoft.winrm4j.client.ntlm.NTCredentialsWithEncryption} will do
 * that by finding the {@link EncryptionAwareHttpEntity}.
 *
 * Code from io.cloudsoft.winrm4j.client.encryption.AsyncHttpEncryptionAwareConduit
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
public class AsyncHttpEncryptionAwareConduit extends AsyncHTTPConduit {

	static final byte[] PRE_AUTH_BOGUS_PAYLOAD = "AWAITING_ENCRYPTION_KEYS".getBytes();

	private static final List<String> TARGET_AUTH_SCHEMES =
			Arrays.asList(AuthSchemes.SPNEGO, AuthSchemes.KERBEROS);

	private static ContentWithType getAppropriate(final Message msg) {
		final EncryptAndSignOutputStream encryptingStream = msg.getContent(EncryptAndSignOutputStream.class);
		if (encryptingStream == null) {
			throw new IllegalStateException("No SignAndEncryptOutInterceptor applied to message");
		}
		return encryptingStream.getAppropriate();
	}

	public AsyncHttpEncryptionAwareConduit(
			final Bus bus,
			final EndpointInfo endpointInfo,
			final EndpointReferenceType endpointReferenceType,
			final AsyncHttpEncryptionAwareConduitFactory factory) throws IOException {
		super(bus, endpointInfo, endpointReferenceType, factory);
	}

	@Override
	protected OutputStream createOutputStream(
			final Message message,
			final boolean needToCacheRequest,
			final boolean isChunking,
			final int chunkThreshold) throws IOException {

		final NtlmEncryptionUtils encryptor = NtlmEncryptionUtils.of(message.get(Credentials.class));
		if (encryptor == null) {
			return super.createOutputStream(message, needToCacheRequest, isChunking, chunkThreshold);
		}

		if (Boolean.TRUE.equals(message.get(USE_ASYNC))) {
			// copied from super, but for our class
			final CXFHttpRequest requestEntity = message.get(CXFHttpRequest.class);
			final AsyncWrappedEncryptionAwareOutputStream out = new AsyncWrappedEncryptionAwareOutputStream(
					message,
					true,
					false,
					chunkThreshold,
					getConduitName(),
					requestEntity.getURI());

			requestEntity.setOutputStream(out);
			return out;
		}

		throw new IllegalStateException("Encryption only available with ASYNC at present");
		// if needed could also subclass the URL stream used by super.super.createOutput
	}

	@Override
	protected void setupConnection(
			final Message message,
			final Address address,
			final HTTPClientPolicy csPolicy) throws IOException {

		super.setupConnection(message, address, csPolicy);

		// replace similar logic in super method, but with a refreshHeaders method available

		final CXFHttpRequest requestEntity = message.get(CXFHttpRequest.class);

		final BasicHttpEntity entity = new EncryptionAwareHttpEntity() {
			@Override
			public boolean isRepeatable() {
				return requestEntity.getOutputStream().retransmitable();
			}

			@Override
			protected ContentWithType getAppropriate() {
				return AsyncHttpEncryptionAwareConduit.getAppropriate(message);
			}
		};
		entity.setChunked(true);
		entity.setContentType((String) message.get(Message.CONTENT_TYPE));

		requestEntity.setEntity(entity);

		requestEntity.setConfig(RequestConfig.copy(requestEntity.getConfig())
				.setTargetPreferredAuthSchemes(TARGET_AUTH_SCHEMES)
				.build());
	}

	private class AsyncWrappedEncryptionAwareOutputStream extends AsyncWrappedOutputStream {

		public AsyncWrappedEncryptionAwareOutputStream(
				final Message message,
				final boolean needToCacheRequest,
				final boolean isChunking,
				final int chunkThreshold,
				final String conduitName,
				final URI uri) {
			super(message, needToCacheRequest, isChunking, chunkThreshold, conduitName, uri);
		}

		@Override
		protected void setupWrappedStream() throws IOException {
			super.setupWrappedStream();

			if (!(cachedStream.getFlowThroughStream() instanceof EncryptionAwareCacheAndWriteOutputStream)) {
				cachedStream =
						new EncryptionAwareCacheAndWriteOutputStream(cachedStream.getFlowThroughStream());
				wrappedStream = cachedStream;
			}
		}

		private class EncryptionAwareCacheAndWriteOutputStream extends CacheAndWriteOutputStream {
			public EncryptionAwareCacheAndWriteOutputStream(OutputStream outbufFlowThroughStream) {
				super(outbufFlowThroughStream);
			}

			@Override
			public byte[] getBytes() throws IOException {
				final ContentWithType appropriate = AsyncHttpEncryptionAwareConduit.getAppropriate(outMessage);
				return appropriate.getPayload();
			}

			@Override
			public InputStream getInputStream() throws IOException {
				return new ByteArrayInputStream(getBytes());
			}
		}
	}
}
