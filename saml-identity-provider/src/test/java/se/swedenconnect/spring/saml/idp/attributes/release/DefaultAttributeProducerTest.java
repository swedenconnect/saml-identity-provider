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
package se.swedenconnect.spring.saml.idp.attributes.release;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * Test cases for DefaultAttributeProducer.
 * 
 * @author Martin Lindström
 */
public class DefaultAttributeProducerTest extends OpenSamlTestBase {

  @Test
  public void testEmpty() {
    
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);
    Mockito.when(details.getAttributes()).thenReturn(Collections.emptyList());
    
    final DefaultAttributeProducer p = new DefaultAttributeProducer();
    final List<Attribute> result = p.releaseAttributes(token);
    Assertions.assertTrue(result.isEmpty());
  }
  
  @Test
  public void testNoAuthnReqs() {
    
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);
    Mockito.when(details.getAttributes()).thenReturn(List.of(new UserAttribute("ID", null, "value")));
    
    Mockito.when(token.getAuthnRequirements()).thenReturn(null);
    
    final DefaultAttributeProducer p = new DefaultAttributeProducer();
    Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> {
      p.releaseAttributes(token);
    });
  }
  
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
    Mockito.when(token.getAuthnRequirements()).thenReturn(reqs);
    
    final DefaultAttributeProducer p = new DefaultAttributeProducer();
    final List<Attribute> result = p.releaseAttributes(token);
    Assertions.assertTrue(result.size() == 2);
    Assertions.assertEquals("ID1", result.get(0).getName());
    Assertions.assertEquals("ID3", result.get(1).getName());
  }
  
}
