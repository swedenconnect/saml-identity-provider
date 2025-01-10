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

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.security.core.Authentication;

import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Test cases for Saml2UserAuthenticationInputToken.
 *
 * @author Martin Lindström
 */
public class Saml2UserAuthenticationInputTokenTest {

  private static final String SP = "https://sp.example.com";

  @Test
  public void test() {

    final Saml2AuthnRequestAuthenticationToken authnRequestToken = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.isAuthenticated()).thenReturn(true);
    Mockito.when(authnRequestToken.getCredentials()).thenReturn("CRED");
    Mockito.when(authnRequestToken.getPrincipal()).thenReturn(SP);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("LOG");

    final EntityDescriptor ed = EntityDescriptorBuilder.builder()
        .entityID(SP)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .extensions(ExtensionsBuilder.builder()
                .extension(UIInfoBuilder.builder()
                    .displayNames(
                        List.of(new LocalizedString("Display name", "en"), new LocalizedString("Visningsnamn", "sv")))
                    .descriptions(List.of(
                        new LocalizedString("Description", "en"), new LocalizedString("Beskrivning", "sv")))
                    .logos(List.of(
                        LogoBuilder.builder()
                            .height(50)
                            .width(50)
                            .url(SP + "/logo.png")
                            .language("en")
                            .build(),
                        LogoBuilder.builder()
                            .height(150)
                            .width(150)
                            .url(SP + "/logo2.png")
                            .build(),
                        LogoBuilder.builder().build()))
                    .build())
                .build())
            .build())
        .build();
    Mockito.when(authnRequestToken.getPeerMetadata()).thenReturn(ed);


    final AuthenticationRequirements authnReqs = Mockito.mock(AuthenticationRequirements.class);

    final Saml2UserAuthenticationInputToken token = new Saml2UserAuthenticationInputToken(authnRequestToken, authnReqs);
    Assertions.assertTrue(token.isAuthenticated());
    Assertions.assertNotNull(token.getAuthnRequestToken());
    Assertions.assertNotNull(token.getAuthnRequirements());
    Assertions.assertNull(token.getUserAuthentication());
    Assertions.assertEquals("CRED", token.getCredentials());
    Assertions.assertEquals(SP, token.getPrincipal());
    Assertions.assertEquals("LOG", token.getLogString());

    Assertions.assertEquals(SP, token.getUiInfo().getEntityId());
    Assertions.assertEquals(SP, token.getUiInfo().getEntityId());

    token.setUserAuthentication(Mockito.mock(Authentication.class));
    Assertions.assertNotNull(token.getUserAuthentication());
  }

}
