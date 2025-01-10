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
package se.swedenconnect.spring.saml.idp.attributes;

import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.saml2.attribute.AttributeTemplate;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeSet;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.metadata.EntityCategoryHelper;

/**
 * Test cases for EntityCategoryRequestedAttributeProcessor.
 *
 * @author Martin Lindström
 */
public class EntityCategoryRequestedAttributeProcessorTest extends OpenSamlTestBase {

  @Test
  public void testNoDeclaredCategories() {

    final EntityDescriptor peerMetadata = EntityDescriptorBuilder.builder()
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getPeerMetadata()).thenReturn(peerMetadata);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final EntityCategoryRequestedAttributeProcessor processor = new EntityCategoryRequestedAttributeProcessor(
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    Assertions.assertTrue(processor.extractRequestedAttributes(token).isEmpty());
  }

  @Test
  public void testNoMatchingCategories() {

    final EntityDescriptor peerMetadata = EntityDescriptorBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_PNR.getUri())
                .build())
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getPeerMetadata()).thenReturn(peerMetadata);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final EntityCategoryRequestedAttributeProcessor processor = new EntityCategoryRequestedAttributeProcessor(
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    Assertions.assertTrue(processor.extractRequestedAttributes(token).isEmpty());
  }

  @Test
  public void testOneMatchingCategory() {

    final EntityDescriptor peerMetadata = EntityDescriptorBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri())
                .build())
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getPeerMetadata()).thenReturn(peerMetadata);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final EntityCategoryRequestedAttributeProcessor processor = new EntityCategoryRequestedAttributeProcessor(
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    final Collection<RequestedAttribute> reqAttrs = processor.extractRequestedAttributes(token);
    Assertions.assertFalse(reqAttrs.isEmpty());

    final AttributeSet as = EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getAttributeSet();
    Assertions.assertEquals(as.getRequiredAttributes().length + as.getRecommendedAttributes().length, reqAttrs.size());

    for (final AttributeTemplate at : as.getRequiredAttributes()) {
      final RequestedAttribute ra =
          reqAttrs.stream().filter(a -> a.getId().equals(at.getName())).findFirst().orElse(null);
      Assertions.assertNotNull(ra, "Expected " + at.getFriendlyName());

      Assertions.assertTrue(ra instanceof ImplicitRequestedAttribute);
      Assertions.assertEquals(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri(),
          ((ImplicitRequestedAttribute) ra).getOrigin());

      Assertions.assertTrue(ra.isRequired(), "Expected " + at.getFriendlyName() + " to be required");
    }
    for (final AttributeTemplate at : as.getRecommendedAttributes()) {
      final RequestedAttribute ra =
          reqAttrs.stream().filter(a -> a.getId().equals(at.getName())).findFirst().orElse(null);
      Assertions.assertNotNull(ra, "Expected " + at.getFriendlyName());
      Assertions.assertFalse(ra.isRequired(), "Expected " + at.getFriendlyName() + " not to be required");
    }

  }

  @Test
  public void testSeveralMatchingCategory() {

    final EntityDescriptor peerMetadata = EntityDescriptorBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri(),
                    EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_EIDAS_NATURAL_PERSON.getUri())
                .build())
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getPeerMetadata()).thenReturn(peerMetadata);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final EntityCategoryRequestedAttributeProcessor processor = new EntityCategoryRequestedAttributeProcessor(
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri(),
            EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_EIDAS_NATURAL_PERSON.getUri()));
    processor.setEntityCategoryRegistry(EntityCategoryHelper.getDefaultEntityCategoryRegistry());

    final Collection<RequestedAttribute> reqAttrs = processor.extractRequestedAttributes(token);
    Assertions.assertFalse(reqAttrs.isEmpty());

    // Date of birth is required for SERVICE_ENTITY_CATEGORY_EIDAS_NATURAL_PERSON but only
    // recommended for SERVICE_ENTITY_CATEGORY_LOA3_PNR -> Should be non-required
    //
    final RequestedAttribute dateOfBirth = reqAttrs.stream()
        .filter(a -> a.getId().equals(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH))
        .findFirst()
        .orElse(null);
    Assertions.assertNotNull(dateOfBirth, "Expected date of birth attribute");
    Assertions.assertFalse(dateOfBirth.isRequired(), "Expected date of birth attribute to be non-required");

    // Given name is required for both categories -> Should be required
    //
    final RequestedAttribute givenName = reqAttrs.stream()
        .filter(a -> a.getId().equals(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME))
        .findFirst()
        .orElse(null);
    Assertions.assertNotNull(givenName, "Expected givenName attribute");
    Assertions.assertTrue(givenName.isRequired(), "Expected givenName attribute to be required");
  }

}
