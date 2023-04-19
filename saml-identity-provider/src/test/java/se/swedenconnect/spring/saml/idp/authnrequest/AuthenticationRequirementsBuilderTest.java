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
package se.swedenconnect.spring.saml.idp.authnrequest;

import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessageMimeTypeEnum;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;

/**
 * Test cases for AuthenticationRequirementsBuilder.
 * 
 * @author Martin Lindström
 */
public class AuthenticationRequirementsBuilderTest {

  @Test
  public void testDefaults() {
    final AuthenticationRequirements ar = AuthenticationRequirementsBuilder.builder().build();

    Assertions.assertFalse(ar.isForceAuthn());
    Assertions.assertFalse(ar.isPassiveAuthn());
    Assertions.assertTrue(ar.getAuthnContextRequirements().isEmpty());
    Assertions.assertTrue(ar.getEntityCategories().isEmpty());
    Assertions.assertTrue(ar.getPrincipalSelectionAttributes().isEmpty());
    Assertions.assertTrue(ar.getRequestedAttributes().isEmpty());
    Assertions.assertNull(ar.getSignatureMessageExtension());
  }

  @Test
  public void test1() {
    final AuthenticationRequirements ar = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(true)
        .passiveAuthn(false)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .entityCategory(EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER.getUri())
        .entityCategory(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri())
        .principalSelectionAttribute(new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER, "191212121212"))
        .requestedAttribute(new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME))
        .signatureMessageExtension(new SignatureMessageExtension(Base64.getEncoder().encodeToString("msg".getBytes()),
            SignMessageMimeTypeEnum.TEXT, false))
        .build();

    Assertions.assertTrue(ar.isForceAuthn());
    Assertions.assertFalse(ar.isPassiveAuthn());
    Assertions.assertEquals(1, ar.getAuthnContextRequirements().size());
    Assertions.assertEquals(2, ar.getEntityCategories().size());
    Assertions.assertTrue(ar.getPrincipalSelectionAttributes().size() == 1);
    Assertions.assertTrue(ar.getRequestedAttributes().size() == 1);
    Assertions.assertNotNull(ar.getSignatureMessageExtension());

    // Test copy ctor
    final AuthenticationRequirements ar2 = AuthenticationRequirementsBuilder.builder(ar)
        .passiveAuthn(true)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)
        .build();

    Assertions.assertTrue(ar2.isForceAuthn());
    Assertions.assertTrue(ar2.isPassiveAuthn());
    Assertions.assertEquals(2, ar2.getAuthnContextRequirements().size());
    Assertions.assertEquals(2, ar2.getEntityCategories().size());
    Assertions.assertTrue(ar2.getPrincipalSelectionAttributes().size() == 1);
    Assertions.assertTrue(ar2.getRequestedAttributes().size() == 1);
    Assertions.assertNotNull(ar2.getSignatureMessageExtension());
  }

  @Test
  public void testLists() {
    final AuthenticationRequirements ar = AuthenticationRequirementsBuilder.builder(null)
        .forceAuthn(true)
        .passiveAuthn(false)
        .authnContextRequirements(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3))
        .entityCategories(List.of(EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER.getUri(),
            EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()))
        .principalSelectionAttributes(List.of(
            new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER, "191212121212")))
        .requestedAttributes(List.of(new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME)))
        .signatureMessageExtension(new SignatureMessageExtension(Base64.getEncoder().encodeToString("msg".getBytes()),
            SignMessageMimeTypeEnum.TEXT, false))
        .build();

    Assertions.assertTrue(ar.isForceAuthn());
    Assertions.assertFalse(ar.isPassiveAuthn());
    Assertions.assertEquals(1, ar.getAuthnContextRequirements().size());
    Assertions.assertEquals(2, ar.getEntityCategories().size());
    Assertions.assertTrue(ar.getPrincipalSelectionAttributes().size() == 1);
    Assertions.assertTrue(ar.getRequestedAttributes().size() == 1);
    Assertions.assertNotNull(ar.getSignatureMessageExtension());
  }

}
