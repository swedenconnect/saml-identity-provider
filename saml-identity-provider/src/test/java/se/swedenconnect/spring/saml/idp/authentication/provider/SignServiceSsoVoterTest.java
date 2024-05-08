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
package se.swedenconnect.spring.saml.idp.authentication.provider;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.SsoVoter.Vote;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Test cases for SignServiceSsoVoter.
 * 
 * @author Martin Lindström
 */
public class SignServiceSsoVoterTest extends OpenSamlTestBase {

  @Test
  public void testSignService() {
    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);

    final Saml2UserAuthenticationInputToken input = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    Mockito.when(input.getLogString()).thenReturn("LOG");
    
    final EntityDescriptor ed = EntityDescriptorBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri())
                .build())
            .build())
        .build();
    
    final Saml2AuthnRequestAuthenticationToken authnRequestToken = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getPeerMetadata()).thenReturn(ed);
    Mockito.when(input.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final SignServiceSsoVoter voter = new SignServiceSsoVoter();
    Assertions.assertEquals(Vote.DENY,
        voter.mayReuse(userAuthn, input, List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)));
  }
  
  @Test
  public void testDontKnow() {
    final Saml2UserAuthentication userAuthn = Mockito.mock(Saml2UserAuthentication.class);

    final Saml2UserAuthenticationInputToken input = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    Mockito.when(input.getLogString()).thenReturn("LOG");
    
    final EntityDescriptor ed = EntityDescriptorBuilder.builder()
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri())
                .build())
            .build())
        .build();
    
    final Saml2AuthnRequestAuthenticationToken authnRequestToken = Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getPeerMetadata()).thenReturn(ed);
    Mockito.when(input.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final SignServiceSsoVoter voter = new SignServiceSsoVoter();
    Assertions.assertEquals(Vote.DONT_KNOW,
        voter.mayReuse(userAuthn, input, List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)));
  }
  
}
