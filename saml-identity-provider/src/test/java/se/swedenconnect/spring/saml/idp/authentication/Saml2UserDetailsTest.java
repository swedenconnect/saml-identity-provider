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
package se.swedenconnect.spring.saml.idp.authentication;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;

/**
 * Test cases for Saml2UserDetails.
 *
 * @author Martin Lindström
 */
public class Saml2UserDetailsTest {

  private static final UserAttribute PNR = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
      AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER, "197309069289");

  private static final UserAttribute GIVEN_NAME = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
      AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, "Nina");

  private static final UserAttribute SN = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_SN,
      AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN, "Greger");

  @Test
  public void testNoAttributes() {

    Assertions.assertEquals("attributes must be set and not empty",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new Saml2UserDetails(Collections.emptyList(), AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
              LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, Instant.now(), "127.0.0.1");
        }).getMessage());
  }

  @Test
  public void testMissingPrimaryAttribute() {
    Assertions.assertEquals("primaryAttribute must be set and appear among the attributes",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new Saml2UserDetails(List.of(PNR, GIVEN_NAME, SN), null,
              LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, Instant.now(), "127.0.0.1");
        }).getMessage());

    Assertions.assertEquals("primaryAttribute must be set and appear among the attributes",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new Saml2UserDetails(List.of(PNR, GIVEN_NAME, SN), AttributeConstants.ATTRIBUTE_NAME_PRID,
              LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, Instant.now(), "127.0.0.1");
        }).getMessage());

    Assertions.assertEquals("primaryAttribute must be set and appear among the attributes",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new Saml2UserDetails(
              List.of(GIVEN_NAME, SN,
                  new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, null)),
              AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
              LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, Instant.now(), "127.0.0.1");
        }).getMessage());
  }

  @Test
  public void testMissingLoa() {
    Assertions.assertEquals("authnContextUri must be set and not empty",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new Saml2UserDetails(List.of(PNR, GIVEN_NAME, SN), AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
              null, Instant.now(), "127.0.0.1");
        }).getMessage());

    Assertions.assertEquals("authnContextUri must be set and not empty",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new Saml2UserDetails(List.of(PNR, GIVEN_NAME, SN), AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
              "", Instant.now(), "127.0.0.1");
        }).getMessage());
  }

  @SuppressWarnings("unlikely-arg-type")
  @Test
  public void test() {
    final Instant now = Instant.now();

    final Saml2UserDetails d =
        new Saml2UserDetails(List.of(PNR, GIVEN_NAME, SN), AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, now, "127.0.0.1");

    Assertions.assertEquals(PNR.getValues().get(0), d.getUsername());
    Assertions.assertEquals(3, d.getAttributes().size());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, d.getPrimaryAttribute());
    Assertions.assertEquals(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3, d.getAuthnContextUri());
    Assertions.assertEquals(now, d.getAuthnInstant());
    Assertions.assertEquals("127.0.0.1", d.getSubjectIpAddress());
    Assertions.assertNull(d.getAuthenticatingAuthority());

    d.setAuthenticatingAuthority("https://idp.example.com");
    Assertions.assertEquals("https://idp.example.com", d.getAuthenticatingAuthority());

    Assertions.assertFalse(d.isSignMessageDisplayed());
    d.setSignMessageDisplayed(true);
    Assertions.assertTrue(d.isSignMessageDisplayed());

    Assertions.assertTrue(d.getAuthorities().isEmpty());
    Assertions.assertEquals("", d.getPassword());
    Assertions.assertTrue(d.isAccountNonExpired());
    Assertions.assertTrue(d.isAccountNonLocked());
    Assertions.assertTrue(d.isCredentialsNonExpired());
    Assertions.assertTrue(d.isEnabled());

    Assertions.assertEquals(Objects.hash(PNR.getValues().get(0)), d.hashCode());

    Assertions.assertFalse(d.equals(null));
    Assertions.assertFalse(d.equals("String"));
    Assertions.assertTrue(d.equals(d));

    final Saml2UserDetails d2 =
        new Saml2UserDetails(List.of(PNR), AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2, now, "127.0.0.1");
    Assertions.assertTrue(d.equals(d2));
  }

}
