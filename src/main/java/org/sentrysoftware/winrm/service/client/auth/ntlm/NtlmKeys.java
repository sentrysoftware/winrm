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

import org.sentrysoftware.winrm.service.client.encryption.ByteArrayUtils;
import org.sentrysoftware.winrm.service.client.encryption.EncryptionUtils;

/**
 * Code from io.cloudsoft.winrm4j.client.ntlm.NtlmKeys
 * release 0.12.3 @link https://github.com/cloudsoft/winrm4j
 */
public class NtlmKeys {

	// adapted from python ntlm-auth
	// also see NTLMEngineImpl.Handle


//	# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
//	# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

	private static final byte[] CLIENT_SIGNING =
			"session key to client-to-server signing key magic constant\0".getBytes();
	private static final byte[] SERVER_SIGNING =
			"session key to server-to-client signing key magic constant\0".getBytes();
	private static final byte[] CLIENT_SEALING =
			"session key to client-to-server sealing key magic constant\0".getBytes();
	private static final byte[] SERVER_SEALING =
			"session key to server-to-client sealing key magic constant\0".getBytes();

	private final byte[] exportedSessionKey;
	private final long negotiateFlags;

	public NtlmKeys(final Type3Message signAndSealData) {
		exportedSessionKey = signAndSealData.getExportedSessionKey();
		negotiateFlags = signAndSealData.getType2Flags();
	}

	public void apply(final NTCredentialsWithEncryption credentials) {
		credentials.setNegotiateFlags(negotiateFlags);

		credentials.setClientSigningKey(getSignKey(CLIENT_SIGNING) );
		credentials.setServerSigningKey(getSignKey(SERVER_SIGNING) );
		credentials.setClientSealingKey(getSealKey(CLIENT_SEALING) );
		credentials.setServerSealingKey(getSealKey(SERVER_SEALING) );
	}

	/**
	 * 
	 * @param magicConstant a constant value set in the MS-NLMP documentation (constants.SignSealConstants)
	 * 
	 * @return Key used to sign messages
	 */
	private byte[] getSignKey(final byte[] magicConstant) {
		return EncryptionUtils.md5digest(ByteArrayUtils.concat(exportedSessionKey, magicConstant));
	}

	/**
	 * Main method to use to calculate the seal_key used to seal (encrypt) messages.
	 * This will determine the correct method below to use based on the compatibility flags set 
	 * and should be called instead of the others
	 * 
	 * @param magicConstant a constant value set in the MS-NLMP documentation (constants.SignSealConstants)
	 * 
	 * @return Key used to seal messages
	 */
	private byte[] getSealKey(final byte[] magicConstant) {

		// This for authentication where NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY has been
		// negotiated. Will weaken the keys if NTLMSSP_NEGOTIATE_128 is not negotiated,
		// will try NEGOTIATE_56 and then will default to the 40-bit key
		if (hasNegotiateFlag(NTLMEngineUtils.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
			if (hasNegotiateFlag(NTLMEngineUtils.NTLMSSP_NEGOTIATE_128)) {
				return EncryptionUtils.md5digest(ByteArrayUtils.concat(exportedSessionKey, magicConstant));

			}
			if (hasNegotiateFlag(NTLMEngineUtils.NTLMSSP_NEGOTIATE_56)) {
				return EncryptionUtils.md5digest(ByteArrayUtils.concat(
						Arrays.copyOfRange(exportedSessionKey, 0, 7),
						magicConstant));
			}
			return EncryptionUtils.md5digest(ByteArrayUtils.concat(
					Arrays.copyOfRange(exportedSessionKey, 0, 5),
					magicConstant));
		}

		// This for authentication where NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		//  has not been negotiated. Will weaken the keys if NTLMSSP_NEGOTIATE_56 is not negotiated it will default
		//  to the 40-bit key.
		if (hasNegotiateFlag(NTLMEngineUtils.NTLMSSP_NEGOTIATE_LM_KEY)) {
			throw new UnsupportedOperationException(
					"LM KEY negotiate mode not implemented; use extended session security instead");
		}

		return exportedSessionKey;
	}

	private boolean hasNegotiateFlag(long flag) {
		return (negotiateFlags & flag)==flag;
	}
}
