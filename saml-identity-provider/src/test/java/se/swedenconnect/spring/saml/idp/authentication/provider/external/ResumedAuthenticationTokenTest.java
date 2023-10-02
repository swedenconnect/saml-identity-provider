/*
 * Copyright 2023 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.spring.saml.idp.authentication.provider.external;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpServletRequest;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Test cases for ResumedAuthenticationToken.
 *
 * @author Martin Lindström
 */
public class ResumedAuthenticationTokenTest {

  @Test
  public void testSuccess() {

    final Authentication authn = Mockito.mock(Authentication.class);
    Mockito.when(authn.getName()).thenReturn("NAME");
    Mockito.when(authn.getAuthorities()).thenReturn(Collections.emptyList());
    Mockito.when(authn.getCredentials()).thenReturn("CRED");
    Mockito.when(authn.getDetails()).thenReturn("DETAILS");
    Mockito.when(authn.getPrincipal()).thenReturn("USER");
    Mockito.when(authn.isAuthenticated()).thenReturn(true);

    final ResumedAuthenticationToken token = new ResumedAuthenticationToken(authn);

    Assertions.assertNotNull(token.getAuthnToken());
    Assertions.assertNull(token.getError());
    Assertions.assertNull(token.getAuthnInputToken());

    token.setAuthnInputToken(Mockito.mock(Saml2UserAuthenticationInputToken.class));
    Assertions.assertNotNull(token.getAuthnInputToken());

    Assertions.assertNull(token.getServletRequest());
    token.setServletRequest(Mockito.mock(HttpServletRequest.class));
    Assertions.assertNotNull(token.getServletRequest());

    Assertions.assertEquals("NAME", token.getName());
    Assertions.assertTrue(token.getAuthorities().isEmpty());
    Assertions.assertEquals("CRED", token.getCredentials());
    Assertions.assertEquals("DETAILS", token.getDetails());
    Assertions.assertEquals("USER", token.getPrincipal());
    Assertions.assertTrue(token.isAuthenticated());
    Assertions.assertThrows(IllegalArgumentException.class, () -> token.setAuthenticated(false));
  }

  @Test
  public void testError() {

    final ResumedAuthenticationToken token = new ResumedAuthenticationToken(
        new Saml2ErrorStatusException(Saml2ErrorStatus.AUTHN_FAILED));

    Assertions.assertNull(token.getAuthnToken());
    Assertions.assertNotNull(token.getError());
    Assertions.assertNull(token.getAuthnInputToken());

    token.setAuthnInputToken(Mockito.mock(Saml2UserAuthenticationInputToken.class));
    Assertions.assertNotNull(token.getAuthnInputToken());

    Assertions.assertEquals("unknown", token.getName());
    Assertions.assertTrue(token.getAuthorities().isEmpty());
    Assertions.assertNull(token.getCredentials());
    Assertions.assertNull(token.getDetails());
    Assertions.assertEquals("saml-error", token.getPrincipal());
    Assertions.assertFalse(token.isAuthenticated());
    Assertions.assertThrows(IllegalArgumentException.class, () -> token.setAuthenticated(false));
  }

}
