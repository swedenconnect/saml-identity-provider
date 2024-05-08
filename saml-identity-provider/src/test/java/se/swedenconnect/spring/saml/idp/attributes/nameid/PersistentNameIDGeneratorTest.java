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
package se.swedenconnect.spring.saml.idp.attributes.nameid;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.NameID;

import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * Test cases for PersistentNameIDGenerator.
 * 
 * @author Martin Lindström
 */
public class PersistentNameIDGeneratorTest extends OpenSamlTestBase {
  
  private static final String IDP = "https://idp.example.com";
  private static final String SP = "https://sp.example.com";

  @Test
  public void test() {
    final PersistentNameIDGenerator gen = new PersistentNameIDGenerator(IDP, SP);
    Assertions.assertEquals(NameID.PERSISTENT, gen.getFormat());
    
    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");
    
    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");    
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);    
    
    final NameID nameId = gen.getNameID(auth);
    Assertions.assertEquals(NameID.PERSISTENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertEquals(SP, nameId.getSPNameQualifier());
  }
  
  @Test
  public void testNoSpQualifier() {
    final PersistentNameIDGenerator gen = new PersistentNameIDGenerator(IDP);
    Assertions.assertEquals(NameID.PERSISTENT, gen.getFormat());
    
    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");
    
    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");    
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);
    
    final NameID nameId = gen.getNameID(auth);
    Assertions.assertEquals(NameID.PERSISTENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertNull(nameId.getSPNameQualifier());
  }
  
  @Test
  public void testNoQualifier() {
    final PersistentNameIDGenerator gen = new PersistentNameIDGenerator(null);
    Assertions.assertEquals(NameID.PERSISTENT, gen.getFormat());
    
    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");
    
    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");    
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);
    
    final NameID nameId = gen.getNameID(auth);
    Assertions.assertEquals(NameID.PERSISTENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());    
    Assertions.assertNull(nameId.getNameQualifier());
    Assertions.assertNull(nameId.getSPNameQualifier());
  }
  
  @Test
  public void testMissingUser() {
    final PersistentNameIDGenerator gen = new PersistentNameIDGenerator(IDP, SP);
    Assertions.assertEquals(NameID.PERSISTENT, gen.getFormat());
    
    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");
    
    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn(null);    
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);    
    
    Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> {
      gen.getNameID(auth);
    });    
  }
  
  @Test
  public void testInvalidHashAlgo() {
    final PersistentNameIDGenerator gen = new PersistentNameIDGenerator(IDP, SP);
    gen.setHashAlgorithm("SHA-257");
    
    Assertions.assertEquals(NameID.PERSISTENT, gen.getFormat());
    
    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getLogString()).thenReturn("logString");
    
    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(auth.getName()).thenReturn("username");    
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);    
    
    Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> {
      gen.getNameID(auth);
    });    
  }
  
}
