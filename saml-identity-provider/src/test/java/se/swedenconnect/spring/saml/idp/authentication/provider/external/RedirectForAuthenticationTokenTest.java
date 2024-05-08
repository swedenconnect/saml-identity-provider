/*
 * Copyright 2023-2024 Sweden Connect
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;

/**
 * Test cases for RedirectForAuthenticationToken.
 * 
 * @author Martin Lindström
 */
public class RedirectForAuthenticationTokenTest {

  @Test
  public void test() {
    
    final Saml2UserAuthenticationInputToken input = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    Mockito.when(input.getName()).thenReturn("TOKEN");
    Mockito.when(input.getCredentials()).thenReturn("CRED");
    Mockito.when(input.getDetails()).thenReturn("DETAILS");
    Mockito.when(input.getPrincipal()).thenReturn("USER");
    
    Assertions.assertEquals("authnPath must be set and begin with a '/'",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new RedirectForAuthenticationToken(input, null, null);
        }).getMessage());
    Assertions.assertEquals("authnPath must be set and begin with a '/'",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new RedirectForAuthenticationToken(input, "authn", null);
        }).getMessage());
    Assertions.assertEquals("resumeAuthnPath must be set and begin with a '/'",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new RedirectForAuthenticationToken(input, "/authn", null);
        }).getMessage());
    Assertions.assertEquals("resumeAuthnPath must be set and begin with a '/'",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new RedirectForAuthenticationToken(input, "/authn", "resume");
        }).getMessage());
    
    final RedirectForAuthenticationToken token =
        new RedirectForAuthenticationToken(input, "/authn", "/resume");
    
    Assertions.assertNotNull(token.getAuthnInputToken());
    Assertions.assertEquals("/authn", token.getAuthnPath());
    Assertions.assertEquals("/resume", token.getResumeAuthnPath());
    Assertions.assertEquals("TOKEN", token.getName());
    Assertions.assertTrue(token.getAuthorities().isEmpty());
    Assertions.assertEquals("CRED", token.getCredentials());
    Assertions.assertEquals("DETAILS", token.getDetails());
    Assertions.assertEquals("USER", token.getPrincipal());
    Assertions.assertFalse(token.isAuthenticated());
    Assertions.assertThrows(IllegalArgumentException.class, () -> token.setAuthenticated(true));
  }

}
