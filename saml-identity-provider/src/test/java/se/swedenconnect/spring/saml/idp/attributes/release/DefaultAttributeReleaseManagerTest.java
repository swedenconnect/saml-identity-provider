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

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;

/**
 * Test cases for DefaultAttributeReleaseManager.
 *
 * @author Martin Lindström
 */
public class DefaultAttributeReleaseManagerTest extends OpenSamlTestBase {

  @Test
  public void test() {

    final List<AttributeProducer> producers = List.of(
        (t) -> List.of(
            AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                .value("191212121212")
                .build(),
            AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)
                .value("Kalle")
                .build()),
        (t) -> List.of(
            AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                .value("191212121212")
                .build(),
            AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_SN)
                .value("Kula")
                .build()));

    final List<AttributeReleaseVoter> voters = List.of(
        (t, a) -> AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME.equals(a.getName())
            ? AttributeReleaseVote.DONT_INCLUDE
            : AttributeReleaseVote.DONT_KNOW,
        (t, a) -> AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER.equals(a.getName())
            ? AttributeReleaseVote.INCLUDE
            : AttributeReleaseVote.DONT_KNOW);

    final DefaultAttributeReleaseManager mgr = new DefaultAttributeReleaseManager(producers, voters);
    Assertions.assertTrue(mgr.getAttributeProducers().size() == 2);
    Assertions.assertTrue(mgr.getAttributeReleaseVoters().size() == 2);

    final List<Attribute> result = mgr.releaseAttributes(Mockito.mock(Saml2UserAuthentication.class));
    Assertions.assertTrue(result.size() == 1);
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, result.get(0).getName());
  }

  @Test
  public void testCtor() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultAttributeReleaseManager(null, null);
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultAttributeReleaseManager(Collections.emptyList(), null);
    });

    DefaultAttributeReleaseManager mgr =
        new DefaultAttributeReleaseManager(List.of((t) -> Collections.emptyList()), null);
    List<AttributeReleaseVoter> voters = mgr.getAttributeReleaseVoters();
    Assertions.assertTrue(voters.size() == 1);
    Assertions.assertTrue(voters.get(0) instanceof IncludeAllAttributeReleaseVoter);

    mgr =
        new DefaultAttributeReleaseManager(List.of((t) -> Collections.emptyList()), Collections.emptyList());
    voters = mgr.getAttributeReleaseVoters();
    Assertions.assertTrue(voters.size() == 1);
    Assertions.assertTrue(voters.get(0) instanceof IncludeAllAttributeReleaseVoter);

  }

}
