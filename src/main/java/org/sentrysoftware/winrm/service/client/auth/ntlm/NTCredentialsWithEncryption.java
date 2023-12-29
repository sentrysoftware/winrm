package org.sentrysoftware.winrm.service.client.auth.ntlm;

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

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;

import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.auth.NTCredentials;

import org.sentrysoftware.winrm.service.client.encryption.EncryptionAwareHttpEntity;
import org.sentrysoftware.winrm.service.client.encryption.EncryptionUtils;

/**
 * NTCredentials with encryption.
 * Code from io.cloudsoft.winrm4j.client.ntlm.NTCredentialsWithEncryption
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
public class NTCredentialsWithEncryption extends NTCredentials {

	private static final long serialVersionUID = 1L;

	private boolean isAuthenticated = false;
	private long negotiateFlags;
	private byte[] clientSigningKey;
	private byte[] serverSigningKey;
	private byte[] clientSealingKey;
	private byte[] serverSealingKey;
	private AtomicLong sequenceNumberIncoming = new AtomicLong(-1);
	private AtomicLong sequenceNumberOutgoing = new AtomicLong(-1);

	public NTCredentialsWithEncryption(
			final String userName,
			final String password,
			final String workstation,
			final String domain) {
		super(userName, password, workstation, domain);
	}

	public boolean isAuthenticated() {
		return isAuthenticated;
	}

	public void setIsAuthenticated(boolean isAuthenticated) {
		this.isAuthenticated = isAuthenticated;
	}

	public void setClientSigningKey(byte[] clientSigningKey) {
		this.clientSigningKey = clientSigningKey;
	}

	public void setServerSigningKey(byte[] serverSigningKey) {
		this.serverSigningKey = serverSigningKey;
	}

	public byte[] getClientSigningKey() {
		return clientSigningKey;
	}

	public byte[] getServerSigningKey() {
		return serverSigningKey;
	}

	public void setClientSealingKey(byte[] clientSealingKey) {
		this.clientSealingKey = clientSealingKey;
	}

	public void setServerSealingKey(byte[] serverSealingKey) {
		this.serverSealingKey = serverSealingKey;
	}

	public byte[] getClientSealingKey() {
		return clientSealingKey;
	}

	public byte[] getServerSealingKey() {
		return serverSealingKey;
	}

	public long getNegotiateFlags() {
		return negotiateFlags;
	}

	public boolean hasNegotiateFlag(long flag) {
		return (getNegotiateFlags() & flag) == flag;
	}

	public void setNegotiateFlags(long negotiateFlags) {
		this.negotiateFlags = negotiateFlags;
	}

	public AtomicLong getSequenceNumberIncoming() {
		return sequenceNumberIncoming;
	}

	public AtomicLong getSequenceNumberOutgoing() {
		return sequenceNumberOutgoing;
	}

	private transient Cipher encryptor;
	public Cipher getStatefulEncryptor() {
		if (encryptor == null) {
			encryptor = EncryptionUtils.arc4(getClientSealingKey());
		}
		return encryptor;
	}

	private transient Cipher decryptor;
	public Cipher getStatefulDecryptor() {
		if (decryptor == null) {
			decryptor = EncryptionUtils.arc4(getServerSealingKey());
		}
		return decryptor;
	}

	void resetEncryption(final HttpRequest request) {
		setIsAuthenticated(false);
		clientSealingKey = null;
		clientSigningKey = null;
		serverSealingKey = null;
		serverSigningKey = null;
		encryptor = null;
		decryptor = null;
		sequenceNumberIncoming.set(-1);
		sequenceNumberOutgoing.set(-1);

		if (request instanceof HttpEntityEnclosingRequest &&
				((HttpEntityEnclosingRequest) request).getEntity() instanceof EncryptionAwareHttpEntity) {
			((EncryptionAwareHttpEntity) ((HttpEntityEnclosingRequest) request).getEntity()).refreshHeaders(
					(HttpEntityEnclosingRequest) request);
		}
	}

	void initEncryption(final Type3Message signAndSealData, final HttpRequest request) {
		setIsAuthenticated(true);
		if (signAndSealData!=null && signAndSealData.getExportedSessionKey()!=null) {
			new NtlmKeys(signAndSealData).apply(this);
		}
		if (request instanceof HttpEntityEnclosingRequest &&
				((HttpEntityEnclosingRequest)request).getEntity() instanceof EncryptionAwareHttpEntity) {
			((EncryptionAwareHttpEntity) ((HttpEntityEnclosingRequest) request).getEntity()).refreshHeaders(
					(HttpEntityEnclosingRequest) request);
		}
	}

	@Override
	public String toString() {
		return getClass().getSimpleName()+super.toString()+"{auth="+isAuthenticated()+"}";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(clientSealingKey);
		result = prime * result + Arrays.hashCode(clientSigningKey);
		result = prime * result + Arrays.hashCode(serverSealingKey);
		result = prime * result + Arrays.hashCode(serverSigningKey);
		result = prime * result
				+ Objects.hash(isAuthenticated, negotiateFlags, sequenceNumberIncoming, sequenceNumberOutgoing);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (!(obj instanceof NTCredentialsWithEncryption))
			return false;
		NTCredentialsWithEncryption other = (NTCredentialsWithEncryption) obj;
		return Arrays.equals(clientSealingKey, other.clientSealingKey)
				&& Arrays.equals(clientSigningKey, other.clientSigningKey) && isAuthenticated == other.isAuthenticated
				&& negotiateFlags == other.negotiateFlags
				&& Objects.equals(sequenceNumberIncoming, other.sequenceNumberIncoming)
				&& Objects.equals(sequenceNumberOutgoing, other.sequenceNumberOutgoing)
				&& Arrays.equals(serverSealingKey, other.serverSealingKey)
				&& Arrays.equals(serverSigningKey, other.serverSigningKey);
	}
}
