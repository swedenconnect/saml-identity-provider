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
package se.swedenconnect.spring.saml.idp.authentication;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.AuthnRequest;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Test cases for Saml2UserAuthentication.
 * 
 * @author Martin Lindström
 */
public class Saml2UserAuthenticationTest {

  @Test
  public void test() {
    
    final Saml2UserDetails userDetails = new Saml2UserDetails(List.of(
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
            "197705232382"),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
            "Frida Kransstege")),
        AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        Instant.now().minusSeconds(10), "235.87.12.4");
    
    final Saml2UserAuthentication a = new Saml2UserAuthentication(userDetails);
    Assertions.assertTrue(a.isAuthenticated());
    Assertions.assertEquals("197705232382", a.getName());
    Assertions.assertTrue(a.isReuseAuthentication());
    Assertions.assertEquals("", a.getCredentials());
    
    a.setReuseAuthentication(false);
    Assertions.assertFalse(a.isReuseAuthentication());
    
    Assertions.assertNull(a.getAuthnRequestToken());
    Assertions.assertNull(a.getAuthenticationInfoTrack());
    
    final Saml2AuthnRequestAuthenticationToken aToken = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(aToken.getEntityId()).thenReturn("SP");
    final AuthnRequest authnRequest = Mockito.mock(AuthnRequest.class);
    Mockito.when(authnRequest.getID()).thenReturn("ID");
    Mockito.when(aToken.getAuthnRequest()).thenReturn(authnRequest);
    a.setAuthnRequestToken(aToken);
    
    Assertions.assertNotNull(a.getAuthnRequestToken());
    Assertions.assertNotNull(a.getAuthenticationInfoTrack());
    Assertions.assertFalse(a.isSsoApplied());
    a.clearAuthnRequestToken();
    Assertions.assertNull(a.getAuthnRequestToken());
    Assertions.assertNotNull(a.getAuthenticationInfoTrack());
    
    a.setAuthnRequestToken(aToken);
    Assertions.assertTrue(a.isSsoApplied());
    a.clearAuthnRequestToken();
    
    Assertions.assertNull(a.getAuthnRequirements());
    a.setAuthnRequirements(Mockito.mock(AuthenticationRequirements.class));
    Assertions.assertNotNull(a.getAuthnRequirements());
    a.clearAuthnRequirements();
    Assertions.assertNull(a.getAuthnRequirements());
  }
  
}
