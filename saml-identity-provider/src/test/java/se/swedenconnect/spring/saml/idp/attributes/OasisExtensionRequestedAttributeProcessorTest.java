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
package se.swedenconnect.spring.saml.idp.attributes;

import java.util.Collection;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.ext.reqattr.RequestedAttributes;
import org.opensaml.saml.saml2.core.AuthnRequest;

import se.swedenconnect.opensaml.saml2.core.build.AuthnRequestBuilder;
import se.swedenconnect.opensaml.saml2.core.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Test class for OasisExtensionRequestedAttributeProcessor.
 * 
 * @author Martin Lindström
 */
public class OasisExtensionRequestedAttributeProcessorTest extends OpenSamlTestBase {
  
  @Test
  public void testNoExtension() {
    
    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .extensions(ExtensionsBuilder.builder()            
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final OasisExtensionRequestedAttributeProcessor processor = new OasisExtensionRequestedAttributeProcessor();

    Assertions.assertTrue(processor.extractRequestedAttributes(token).isEmpty());
  }
  
  @Test
  public void testNoExtension2() {
    
    final RequestedAttributes ra = (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
    
    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(ra)
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final OasisExtensionRequestedAttributeProcessor processor = new OasisExtensionRequestedAttributeProcessor();

    Assertions.assertTrue(processor.extractRequestedAttributes(token).isEmpty());
  }
  
  @Test
  public void testExtension() {
    
    final RequestedAttributes ra = (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);    
    final org.opensaml.saml.saml2.metadata.RequestedAttribute r1 = (org.opensaml.saml.saml2.metadata.RequestedAttribute)
        XMLObjectSupport.buildXMLObject(org.opensaml.saml.saml2.metadata.RequestedAttribute.DEFAULT_ELEMENT_NAME);
    r1.setIsRequired(true);
    r1.setName(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER);
    ra.getRequestedAttributes().add(r1);
    final org.opensaml.saml.saml2.metadata.RequestedAttribute r2 = (org.opensaml.saml.saml2.metadata.RequestedAttribute)
        XMLObjectSupport.buildXMLObject(org.opensaml.saml.saml2.metadata.RequestedAttribute.DEFAULT_ELEMENT_NAME);
    r2.setIsRequired(true);
    r2.setName(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME);
    ra.getRequestedAttributes().add(r2);
    
    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(ra)
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final OasisExtensionRequestedAttributeProcessor processor = new OasisExtensionRequestedAttributeProcessor();
    final Collection<RequestedAttribute> attrs = processor.extractRequestedAttributes(token); 
    
    Assertions.assertEquals(2, attrs.size());
    
  }

}
