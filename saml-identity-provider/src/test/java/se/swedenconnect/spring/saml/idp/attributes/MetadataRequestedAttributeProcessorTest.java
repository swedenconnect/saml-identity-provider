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
package se.swedenconnect.spring.saml.idp.attributes;

import java.util.Collection;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.saml2.core.build.AuthnRequestBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.RequestedAttributeBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Test cases for MetadataRequestedAttributeProcessor.
 * 
 * @author Martin Lindström
 */
public class MetadataRequestedAttributeProcessorTest extends OpenSamlTestBase {

  @Test
  public void testNoAcs() {
    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .build();
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getPeerMetadata()).thenReturn(metadata);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final MetadataRequestedAttributeProcessor processor = new MetadataRequestedAttributeProcessor();

    Assertions.assertTrue(processor.extractRequestedAttributes(token).isEmpty());
  }

  @Test
  public void testNoIndexWithDefault() {
    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .build();
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .attributeConsumingServices(
                AttributeConsumingServiceBuilder.builder()
                    .index(1)
                    .isDefault(false)
                    .requestedAttributes(
                        RequestedAttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH)
                            .isRequired(true)
                            .build())
                    .build(),
                AttributeConsumingServiceBuilder.builder()
                    .index(2)
                    .isDefault(true)
                    .requestedAttributes(
                        RequestedAttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                            .isRequired(true)
                            .build())
                    .build())
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getPeerMetadata()).thenReturn(metadata);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final MetadataRequestedAttributeProcessor processor = new MetadataRequestedAttributeProcessor();

    Collection<RequestedAttribute> attrs = processor.extractRequestedAttributes(token); 
    
    Assertions.assertEquals(1, attrs.size());
    Assertions.assertTrue(attrs.stream()
        .filter(r -> r.getId().equals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER))
        .findFirst()
        .isPresent());
  }
  
  @Test
  public void testNoIndexNoDefault() {
    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .build();
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .attributeConsumingServices(
                AttributeConsumingServiceBuilder.builder()
                .index(3)
                .isDefault(false)
                .requestedAttributes(
                    RequestedAttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_C)
                        .isRequired(true)
                        .build())
                .build(),
                AttributeConsumingServiceBuilder.builder()
                    .index(1)
                    .isDefault(false)
                    .requestedAttributes(
                        RequestedAttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH)
                            .isRequired(true)
                            .build())
                    .build(),
                AttributeConsumingServiceBuilder.builder()
                    .index(2)
                    .isDefault(false)
                    .requestedAttributes(
                        RequestedAttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                            .isRequired(true)
                            .build())
                    .build())
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getPeerMetadata()).thenReturn(metadata);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final MetadataRequestedAttributeProcessor processor = new MetadataRequestedAttributeProcessor();

    Collection<RequestedAttribute> attrs = processor.extractRequestedAttributes(token); 
    
    Assertions.assertEquals(1, attrs.size());
    Assertions.assertTrue(attrs.stream()
        .filter(r -> r.getId().equals(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH))
        .findFirst()
        .isPresent());
  }
  
  @Test
  public void testWithIndex() {
    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .attributeConsumerServiceIndex(2)
        .build();
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .attributeConsumingServices(
                AttributeConsumingServiceBuilder.builder()
                .index(3)
                .isDefault(true)
                .requestedAttributes(
                    RequestedAttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_C)
                        .isRequired(true)
                        .build())
                .build(),
                AttributeConsumingServiceBuilder.builder()
                    .index(1)
                    .isDefault(false)
                    .requestedAttributes(
                        RequestedAttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH)
                            .isRequired(true)
                            .build())
                    .build(),
                AttributeConsumingServiceBuilder.builder()
                    .index(2)
                    .isDefault(false)
                    .requestedAttributes(
                        RequestedAttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                            .isRequired(true)
                            .build())
                    .build())
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getPeerMetadata()).thenReturn(metadata);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final MetadataRequestedAttributeProcessor processor = new MetadataRequestedAttributeProcessor();

    Collection<RequestedAttribute> attrs = processor.extractRequestedAttributes(token); 
    
    Assertions.assertEquals(1, attrs.size());
    Assertions.assertTrue(attrs.stream()
        .filter(r -> r.getId().equals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER))
        .findFirst()
        .isPresent());
  }  

}
