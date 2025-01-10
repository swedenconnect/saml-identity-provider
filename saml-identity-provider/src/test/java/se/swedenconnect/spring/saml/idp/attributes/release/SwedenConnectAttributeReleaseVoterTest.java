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
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Test cases for SwedenConnectAttributeReleaseVoter.
 *
 * @author Martin Lindström
 */
public class SwedenConnectAttributeReleaseVoterTest extends OpenSamlTestBase {

  @Test
  public void testMissingPnrValue() {

    final Saml2UserAuthentication authn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken req = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(req.getLogString()).thenReturn("logstring");
    Mockito.when(authn.getAuthnRequestToken()).thenReturn(req);

    final Attribute pnr = AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
        .build();

    final SwedenConnectAttributeReleaseVoter voter = new SwedenConnectAttributeReleaseVoter();
    Assertions.assertEquals(AttributeReleaseVote.DONT_INCLUDE, voter.vote(authn, pnr));
  }

  @Test
  public void testPnrValue() {

    final Saml2UserAuthentication authn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken req = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(req.getLogString()).thenReturn("logstring");
    Mockito.when(authn.getAuthnRequestToken()).thenReturn(req);

    final Attribute pnr = AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
        .value("191212121212")
        .build();

    final SwedenConnectAttributeReleaseVoter voter = new SwedenConnectAttributeReleaseVoter();
    Assertions.assertEquals(AttributeReleaseVote.DONT_KNOW, voter.vote(authn, pnr));
  }

  @Test
  public void testPnrValueBadFormat() {

    final Saml2UserAuthentication authn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken req = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(req.getLogString()).thenReturn("logstring");
    Mockito.when(authn.getAuthnRequestToken()).thenReturn(req);

    final Attribute pnr = AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
        .value("LLQQÅÅPPCBAB")
        .build();

    final Attribute pnr2 = AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
        .value("123456789")
        .build();

    final SwedenConnectAttributeReleaseVoter voter = new SwedenConnectAttributeReleaseVoter();
    Assertions.assertEquals(AttributeReleaseVote.DONT_KNOW, voter.vote(authn, pnr));
    Assertions.assertEquals(AttributeReleaseVote.DONT_KNOW, voter.vote(authn, pnr2));
  }

  @Test
  public void testOtherAttribute() {

    final Saml2UserAuthentication authn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken req = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(req.getLogString()).thenReturn("logstring");
    Mockito.when(authn.getAuthnRequestToken()).thenReturn(req);

    final Attribute pnr = AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)
        .value("Kalle")
        .build();

    final SwedenConnectAttributeReleaseVoter voter = new SwedenConnectAttributeReleaseVoter();
    Assertions.assertEquals(AttributeReleaseVote.DONT_KNOW, voter.vote(authn, pnr));
  }

  @Test
  public void testCoordinationNumberNotDeclaredSupport() {

    final Saml2UserAuthentication authn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken req = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(req.getLogString()).thenReturn("logstring");
    Mockito.when(authn.getAuthnRequestToken()).thenReturn(req);

    final AuthenticationRequirements authnRequirements = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(authnRequirements.getEntityCategories()).thenReturn(Collections.emptyList());
    Mockito.when(authn.getAuthnRequirements()).thenReturn(authnRequirements);

    final Attribute pnr = AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
        .value("197010632391")
        .build();

    final SwedenConnectAttributeReleaseVoter voter = new SwedenConnectAttributeReleaseVoter();
    Assertions.assertEquals(AttributeReleaseVote.DONT_INCLUDE, voter.vote(authn, pnr));
  }

  @Test
  public void testCoordinationNumberDeclaredSupport() {

    final Saml2UserAuthentication authn = Mockito.mock(Saml2UserAuthentication.class);
    final Saml2AuthnRequestAuthenticationToken req = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(req.getLogString()).thenReturn("logstring");
    Mockito.when(authn.getAuthnRequestToken()).thenReturn(req);

    final AuthenticationRequirements authnRequirements = Mockito.mock(AuthenticationRequirements.class);
    Mockito.when(authnRequirements.getEntityCategories())
        .thenReturn(List.of(EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER.getUri()));
    Mockito.when(authn.getAuthnRequirements()).thenReturn(authnRequirements);

    final Attribute pnr = AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
        .value("197010632391")
        .build();

    final SwedenConnectAttributeReleaseVoter voter = new SwedenConnectAttributeReleaseVoter();
    Assertions.assertEquals(AttributeReleaseVote.DONT_KNOW, voter.vote(authn, pnr));
  }

}
