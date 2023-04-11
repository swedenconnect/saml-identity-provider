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
package se.swedenconnect.spring.saml.idp.attributes.release;

import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessageMimeTypeEnum;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;

/**
 * Test cases for SwedenConnectAttributeProducer.
 * 
 * @author Martin Lindström
 */
public class SwedenConnectAttributeProducerTest extends OpenSamlTestBase {

  @Test
  public void testRelease() {
    
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);
    Mockito.when(details.getAttributes()).thenReturn(List.of(
        new UserAttribute("ID1", null, "value1"),
        new UserAttribute("ID2", null, "value2"),
        new UserAttribute("ID3", null, "value3")));
    
    final AuthenticationRequirements reqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(reqs.getRequestedAttributes()).thenReturn(List.of(
        new RequestedAttribute("ID1"),
        new RequestedAttribute("ID3")));
    Mockito.when(reqs.getSignatureMessageExtension()).thenReturn(null);
    
    Mockito.when(token.getAuthnRequirements()).thenReturn(reqs);
    
    final SwedenConnectAttributeProducer p = new SwedenConnectAttributeProducer();
    final List<Attribute> result = p.releaseAttributes(token);
    Assertions.assertTrue(result.size() == 2);
    Assertions.assertEquals("ID1", result.get(0).getName());
    Assertions.assertEquals("ID3", result.get(1).getName());
  }
  
  @Test
  public void testReleaseWithSignMessageDigest() {
    
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);    
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);
    Mockito.when(details.getAttributes()).thenReturn(List.of(
        new UserAttribute("ID1", null, "value1"),
        new UserAttribute("ID2", null, "value2"),
        new UserAttribute("ID3", null, "value3")));
    Mockito.when(details.isSignMessageDisplayed()).thenReturn(true);
    
    final AuthenticationRequirements reqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(reqs.getRequestedAttributes()).thenReturn(List.of(
        new RequestedAttribute("ID1"),
        new RequestedAttribute("ID3")));
    
    final SignatureMessageExtension sm = new SignatureMessageExtension(Base64.getEncoder().encodeToString("Sign Message".getBytes()),
        SignMessageMimeTypeEnum.TEXT, true);
    
    Mockito.when(reqs.getSignatureMessageExtension()).thenReturn(sm);
    
    Mockito.when(token.getAuthnRequirements()).thenReturn(reqs);
    
    final SwedenConnectAttributeProducer p = new SwedenConnectAttributeProducer();
    final List<Attribute> result = p.releaseAttributes(token);
    Assertions.assertTrue(result.size() == 3);
    Assertions.assertEquals("ID1", result.get(0).getName());
    Assertions.assertEquals("ID3", result.get(1).getName());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST, result.get(2).getName());
  }
  
  @Test
  public void testReleaseWithSignMessageDigestNotDisplayed() {
    
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);    
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);
    Mockito.when(details.getAttributes()).thenReturn(List.of(
        new UserAttribute("ID1", null, "value1"),
        new UserAttribute("ID2", null, "value2"),
        new UserAttribute("ID3", null, "value3")));
    Mockito.when(details.isSignMessageDisplayed()).thenReturn(false);
    
    final AuthenticationRequirements reqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(reqs.getRequestedAttributes()).thenReturn(List.of(
        new RequestedAttribute("ID1"),
        new RequestedAttribute("ID3")));
    
    final SignatureMessageExtension sm = new SignatureMessageExtension(Base64.getEncoder().encodeToString("Sign Message".getBytes()),
        SignMessageMimeTypeEnum.TEXT, false);
    
    Mockito.when(reqs.getSignatureMessageExtension()).thenReturn(sm);
    
    Mockito.when(token.getAuthnRequirements()).thenReturn(reqs);
    
    final SwedenConnectAttributeProducer p = new SwedenConnectAttributeProducer();
    final List<Attribute> result = p.releaseAttributes(token);
    Assertions.assertTrue(result.size() == 2);
  }
  
  @Test
  public void testReleaseWithSignMessageFailureIgnored() {
    
    final Saml2AuthnRequestAuthenticationToken reqToken = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(reqToken.getLogString()).thenReturn("logstring");
    
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(token.getAuthnRequestToken()).thenReturn(reqToken);
    
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);    
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);
    Mockito.when(details.getAttributes()).thenReturn(List.of(
        new UserAttribute("ID1", null, "value1"),
        new UserAttribute("ID2", null, "value2"),
        new UserAttribute("ID3", null, "value3")));
    Mockito.when(details.isSignMessageDisplayed()).thenReturn(true);
    
    final AuthenticationRequirements reqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(reqs.getRequestedAttributes()).thenReturn(List.of(
        new RequestedAttribute("ID1"),
        new RequestedAttribute("ID3")));
    
    final SignatureMessageExtension sm = Mockito.mock(SignatureMessageExtension.class);
    Mockito.when(sm.getMessage()).thenReturn(null);
    Mockito.when(sm.isMustShow()).thenReturn(false);
    
    Mockito.when(reqs.getSignatureMessageExtension()).thenReturn(sm);
    
    Mockito.when(token.getAuthnRequirements()).thenReturn(reqs);
    
    final SwedenConnectAttributeProducer p = new SwedenConnectAttributeProducer();
    final List<Attribute> result = p.releaseAttributes(token);
    Assertions.assertTrue(result.size() == 2);
  }
  
  @Test
  public void testReleaseWithSignMessageFailure() {
    
    final Saml2AuthnRequestAuthenticationToken reqToken = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(reqToken.getLogString()).thenReturn("logstring");
    
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(token.getAuthnRequestToken()).thenReturn(reqToken);
    
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);    
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);
    Mockito.when(details.getAttributes()).thenReturn(List.of(
        new UserAttribute("ID1", null, "value1"),
        new UserAttribute("ID2", null, "value2"),
        new UserAttribute("ID3", null, "value3")));
    Mockito.when(details.isSignMessageDisplayed()).thenReturn(true);
    
    final AuthenticationRequirements reqs = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(reqs.getRequestedAttributes()).thenReturn(List.of(
        new RequestedAttribute("ID1"),
        new RequestedAttribute("ID3")));
    
    final SignatureMessageExtension sm = Mockito.mock(SignatureMessageExtension.class);
    Mockito.when(sm.getMessage()).thenReturn(null);
    Mockito.when(sm.isMustShow()).thenReturn(true);
    
    Mockito.when(reqs.getSignatureMessageExtension()).thenReturn(sm);
    
    Mockito.when(token.getAuthnRequirements()).thenReturn(reqs);
    
    final SwedenConnectAttributeProducer p = new SwedenConnectAttributeProducer();
    
    final Status status = Assertions.assertThrows(Saml2ErrorStatusException.class, () -> {
      p.releaseAttributes(token);
    }).getStatus();
    Assertions.assertEquals(StatusCode.REQUEST_UNSUPPORTED, status.getStatusCode().getStatusCode().getValue());
    Assertions.assertEquals(Saml2ErrorStatus.SIGN_MESSAGE.getDefaultStatusMessage(), status.getStatusMessage().getValue()); 
  }  
  
}
