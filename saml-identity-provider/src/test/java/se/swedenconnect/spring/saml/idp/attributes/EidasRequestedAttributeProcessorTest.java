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
import org.opensaml.saml.saml2.core.AuthnRequest;

import se.swedenconnect.opensaml.eidas.ext.RequestedAttributes;
import se.swedenconnect.opensaml.saml2.core.build.AuthnRequestBuilder;
import se.swedenconnect.opensaml.saml2.core.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Test cases for EidasRequestedAttributeProcessor.
 *
 * @author Martin Lindström
 */
public class EidasRequestedAttributeProcessorTest extends OpenSamlTestBase {

  @Test
  public void testNoExtension() {

    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .extensions(ExtensionsBuilder.builder().build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);

    final EidasRequestedAttributeProcessor processor = new EidasRequestedAttributeProcessor();

    Assertions.assertTrue(processor.extractRequestedAttributes(token).isEmpty());
  }

  @Test
  public void testExtension() {
    final RequestedAttributes rattrs = (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
    final se.swedenconnect.opensaml.eidas.ext.RequestedAttribute r1 = (se.swedenconnect.opensaml.eidas.ext.RequestedAttribute)
        XMLObjectSupport.buildXMLObject(se.swedenconnect.opensaml.eidas.ext.RequestedAttribute.DEFAULT_ELEMENT_NAME);
    r1.setName(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER);
    r1.setIsRequired(true);
    rattrs.getRequestedAttributes().add(r1);

    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(rattrs)
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final EidasRequestedAttributeProcessor processor = new EidasRequestedAttributeProcessor();
    Collection<RequestedAttribute> attrs = processor.extractRequestedAttributes(token);

    Assertions.assertTrue(attrs.size() == 1);
    Assertions.assertTrue(attrs.stream()
        .filter(a -> a.getId().equals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER))
        .map(a -> a.isRequired())
        .findFirst()
        .orElse(false));



  }

}
