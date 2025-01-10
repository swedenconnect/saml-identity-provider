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
import org.opensaml.saml.saml2.core.AuthnRequest;

import se.swedenconnect.opensaml.saml2.core.build.AuthnRequestBuilder;
import se.swedenconnect.opensaml.saml2.core.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Test cases for DefaultPrincipalSelectionProcessor
 *
 * @author Martin Lindström
 */
public class DefaultPrincipalSelectionProcessorTest extends OpenSamlTestBase {

  @Test
  public void noPrincipalSelection() {

    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);

    final DefaultPrincipalSelectionProcessor processor = new DefaultPrincipalSelectionProcessor();

    Assertions.assertTrue(processor.extractPrincipalSelection(token).isEmpty());
  }

  @Test
  public void noPrincipalSelection2() {

    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .extensions(ExtensionsBuilder.builder().build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);

    final DefaultPrincipalSelectionProcessor processor = new DefaultPrincipalSelectionProcessor();

    Assertions.assertTrue(processor.extractPrincipalSelection(token).isEmpty());
  }

  @Test
  public void listPrincipalSelection() {

    final AuthnRequest authnRequest = AuthnRequestBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(PrincipalSelectionBuilder.builder()
                .matchValues(List.of(
                    MatchValueBuilder.builder()
                        .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                        .value("191212121212")
                        .build(),
                    MatchValueBuilder.builder()
                        .name(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME)
                        .value("Bo Ko")
                        .build()))
                .build())
            .build())
        .build();

    final Saml2AuthnRequestAuthenticationToken token = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(token.getAuthnRequest()).thenReturn(authnRequest);
    Mockito.when(token.getLogString()).thenReturn("logstring");

    final DefaultPrincipalSelectionProcessor processor = new DefaultPrincipalSelectionProcessor();

    final Collection<UserAttribute> attributes = processor.extractPrincipalSelection(token);
    Assertions.assertEquals(2, attributes.size());
    Assertions.assertEquals("191212121212", attributes.stream()
        .filter(u -> AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER.equals(u.getId()))
        .map(UserAttribute::getValues)
        .map(v -> v.get(0))
        .map(String.class::cast)
        .findFirst()
        .orElse("not-found"));
    Assertions.assertEquals("Bo Ko", attributes.stream()
        .filter(u -> AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME.equals(u.getId()))
        .map(UserAttribute::getValues)
        .map(v -> v.get(0))
        .map(String.class::cast)
        .findFirst()
        .orElse("not-found"));

  }

}
