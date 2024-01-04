package org.sentrysoftware.winrm.service.client.auth;

import static org.sentrysoftware.winrm.Utils.EMPTY;
import static org.sentrysoftware.winrm.service.client.auth.AuthenticationEnum.KERBEROS;
import static org.sentrysoftware.winrm.service.client.auth.AuthenticationEnum.NTLM;
import static org.sentrysoftware.winrm.service.client.auth.AuthenticationEnum.getValueOf;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AuthenticationEnumTest {

	@Test
	void testGetValueOf() {
		assertEquals(empty(), getValueOf(null));
		assertEquals(empty(), getValueOf(EMPTY));
		assertEquals(empty(), getValueOf("unknown"));
		assertEquals(of(NTLM), getValueOf(" ntlm "));
		assertEquals(of(NTLM), getValueOf(" Ntlm "));
		assertEquals(of(NTLM), getValueOf(" NTLM "));
		assertEquals(of(KERBEROS), getValueOf(" kerberos "));
		assertEquals(of(KERBEROS), getValueOf(" Kerberos "));
		assertEquals(of(KERBEROS), getValueOf(" KERBEROS "));
	}
}
