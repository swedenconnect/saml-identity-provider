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
package se.swedenconnect.spring.saml.idp.authentication;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Status;

import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;

/**
 * Test cases for SwedenConnectPostAuthenticationProcessor.
 * 
 * @author Martin Lindström
 */
public class SwedenConnectPostAuthenticationProcessorTest extends OpenSamlTestBase {

  @Test
  public void testNoSignMessage() {
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("LOG");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final AuthenticationRequirements authnReq = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(authnReq.getSignatureMessageExtension()).thenReturn(null);
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReq);

    final SwedenConnectPostAuthenticationProcessor p = new SwedenConnectPostAuthenticationProcessor();

    Assertions.assertDoesNotThrow(() -> {
      p.process(token);
    });
  }
  
  @Test
  public void testSignMessageDontHaveToDisplay() {
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("LOG");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);
    
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.isSignMessageDisplayed()).thenReturn(false);
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);

    final AuthenticationRequirements authnReq = Mockito.mock(AuthenticationRequirements.class);
    final SignatureMessageExtension sm = Mockito.mock(SignatureMessageExtension.class);
    Mockito.when(sm.isMustShow()).thenReturn(false);
    
    Mockito.when(authnReq.getSignatureMessageExtension()).thenReturn(sm);
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReq);

    final SwedenConnectPostAuthenticationProcessor p = new SwedenConnectPostAuthenticationProcessor();

    Assertions.assertDoesNotThrow(() -> {
      p.process(token);
    });
  }
  
  @Test
  public void testSignMessageWasDisplayed() {
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("LOG");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);
    
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.isSignMessageDisplayed()).thenReturn(true);
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);

    final AuthenticationRequirements authnReq = Mockito.mock(AuthenticationRequirements.class);
    final SignatureMessageExtension sm = Mockito.mock(SignatureMessageExtension.class);
    Mockito.when(sm.isMustShow()).thenReturn(true);
    
    Mockito.when(authnReq.getSignatureMessageExtension()).thenReturn(sm);
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReq);

    final SwedenConnectPostAuthenticationProcessor p = new SwedenConnectPostAuthenticationProcessor();

    Assertions.assertDoesNotThrow(() -> {
      p.process(token);
    });
  }
  
  @Test
  public void testSignMessageHaveToDisplay() {
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("LOG");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);
    
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.isSignMessageDisplayed()).thenReturn(false);
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);

    final AuthenticationRequirements authnReq = Mockito.mock(AuthenticationRequirements.class);
    final SignatureMessageExtension sm = Mockito.mock(SignatureMessageExtension.class);
    Mockito.when(sm.isMustShow()).thenReturn(true);
    
    Mockito.when(authnReq.getSignatureMessageExtension()).thenReturn(sm);
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReq);

    final SwedenConnectPostAuthenticationProcessor p = new SwedenConnectPostAuthenticationProcessor();

    final Status status = Assertions.assertThrows(Saml2ErrorStatusException.class, () -> {
      p.process(token);
    }).getStatus();
    Assertions.assertEquals(Saml2ErrorStatus.SIGN_MESSAGE_NOT_DISPLAYED.getSubStatusCode(),
        status.getStatusCode().getStatusCode().getValue());
  }

}
