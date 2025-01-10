/*
 * Copyright 2023-2025 Sweden Connect
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

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;

/**
 * Test cases for ReleaseAllAttributeProducer.
 *
 * @author Martin Lindström
 */
public class ReleaseAllAttributeProducerTest extends OpenSamlTestBase {

  @Test
  public void testRelease() {
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(token.getSaml2UserDetails()).thenReturn(details);
    Mockito.when(details.getAttributes()).thenReturn(List.of(
        new UserAttribute("ID1", null, "value1"),
        new UserAttribute("ID2", null, "value2"),
        new UserAttribute("ID3", null, "value3")));

    final ReleaseAllAttributeProducer p = new ReleaseAllAttributeProducer();
    final List<Attribute> result = p.releaseAttributes(token);
    Assertions.assertTrue(result.size() == 3);
    Assertions.assertEquals("ID1", result.get(0).getName());
    Assertions.assertEquals("ID2", result.get(1).getName());
    Assertions.assertEquals("ID3", result.get(2).getName());
  }

}
