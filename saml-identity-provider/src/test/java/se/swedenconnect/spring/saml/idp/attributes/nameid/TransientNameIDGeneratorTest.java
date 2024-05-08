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

/**
 * Test cases for TransientNameIDGenerator.
 * 
 * @author Martin Lindström
 */
public class TransientNameIDGeneratorTest extends OpenSamlTestBase {
  
  private static final String IDP = "https://idp.example.com";
  private static final String SP = "https://sp.example.com";

  @Test
  public void test() {
    final TransientNameIDGenerator gen = new TransientNameIDGenerator(IDP, SP);
    Assertions.assertEquals(NameID.TRANSIENT, gen.getFormat());
    
    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);
    Mockito.when(token.getLogString()).thenReturn("logString");
    
    final NameID nameId = gen.getNameID(auth);
    Assertions.assertEquals(NameID.TRANSIENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertEquals(SP, nameId.getSPNameQualifier());
  }
  
  @Test
  public void test2() {
    final TransientNameIDGenerator gen = new TransientNameIDGenerator(IDP);
    Assertions.assertEquals(NameID.TRANSIENT, gen.getFormat());
    
    final Saml2UserAuthentication auth = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(auth.getAuthnRequestToken()).thenReturn(token);
    Mockito.when(token.getLogString()).thenReturn("logString");
    
    final NameID nameId = gen.getNameID(auth);
    Assertions.assertEquals(NameID.TRANSIENT, nameId.getFormat());
    Assertions.assertNotNull(nameId.getValue());
    Assertions.assertEquals(IDP, nameId.getNameQualifier());
    Assertions.assertNull(nameId.getSPNameQualifier());
  }
  
}
