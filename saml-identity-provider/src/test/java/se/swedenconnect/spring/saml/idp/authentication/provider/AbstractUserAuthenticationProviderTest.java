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

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Status;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;
import se.swedenconnect.spring.saml.idp.authentication.provider.SsoVoter.Vote;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirementsBuilder;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Test cases for AbstractUserAuthenticationProvider.
 * 
 * @author Martin Lindström
 */
public class AbstractUserAuthenticationProviderTest extends OpenSamlTestBase {

  private static final String PNR = "197309069289";

  @Test
  public void testNoSupportedLoas() {

    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    Assertions.assertNull(provider.authenticate(token));
  }

  @Test
  public void testSso() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(false)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final Saml2UserAuthentication sso = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(sso.isReuseAuthentication()).thenReturn(true);
    Mockito.when(sso.getName()).thenReturn("SSO-USER");

    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(Instant.now().minus(Duration.ofMinutes(30)));
    Mockito.when(details.getAuthnContextUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(sso.getSaml2UserDetails()).thenReturn(details);

    Mockito.when(token.getUserAuthentication()).thenReturn(sso);

    final Authentication result = provider.authenticate(token);
    Assertions.assertTrue(result instanceof Saml2UserAuthentication);
    Assertions.assertEquals("SSO-USER", result.getName());
  }

  @Test
  public void testAuthenticate() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    Assertions.assertTrue(provider.supports(Saml2UserAuthenticationInputToken.class));
    Assertions.assertFalse(provider.supports(Authentication.class));
    
    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(false)
        .passiveAuthn(false)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    Mockito.when(token.getUserAuthentication()).thenReturn(null);

    final Authentication result = provider.authenticate(token);
    Assertions.assertTrue(result instanceof Saml2UserAuthentication);
    Assertions.assertEquals(PNR, result.getName());
  }
  
  @Test
  public void testWrongType() {
    
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));
    
    Assertions.assertNull(provider.authenticate(Mockito.mock(Saml2AuthnRequestAuthenticationToken.class)));
  }
  
  @Test
  public void testAuthenticateNoAuthnContextSpecified() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(true)
        .passiveAuthn(false)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    Mockito.when(token.getUserAuthentication()).thenReturn(null);

    final Authentication result = provider.authenticate(token);
    Assertions.assertTrue(result instanceof Saml2UserAuthentication);
    Assertions.assertEquals(PNR, result.getName());
  }  

  @Test
  public void testIsPassive() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(false)
        .passiveAuthn(true)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    Mockito.when(token.getUserAuthentication()).thenReturn(null);

    final Status status = Assertions.assertThrows(Saml2ErrorStatusException.class, () -> {
      provider.authenticate(token);
    }).getStatus();
    Assertions.assertEquals(Saml2ErrorStatus.PASSIVE_AUTHN.getSubStatusCode(),
        status.getStatusCode().getStatusCode().getValue());
  }
  
  @Test
  public void testNoSsoForceAuthn() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(true)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final Saml2UserAuthentication sso = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(sso.isReuseAuthentication()).thenReturn(true);
    Mockito.when(sso.getName()).thenReturn("SSO-USER");

    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(Instant.now().minus(Duration.ofMinutes(30)));
    Mockito.when(details.getAuthnContextUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(sso.getSaml2UserDetails()).thenReturn(details);

    Mockito.when(token.getUserAuthentication()).thenReturn(sso);

    final Authentication result = provider.authenticate(token);
    Assertions.assertTrue(result instanceof Saml2UserAuthentication);
    Assertions.assertEquals(PNR, result.getName());
  }
  
  @Test
  public void testNoSsoNotSaml2UserAuthentication() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(false)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final UsernamePasswordAuthenticationToken sso = Mockito.mock(UsernamePasswordAuthenticationToken.class); 
    Mockito.when(sso.getName()).thenReturn("SSO-USER");

    Mockito.when(token.getUserAuthentication()).thenReturn(sso);

    final Authentication result = provider.authenticate(token);
    Assertions.assertTrue(result instanceof Saml2UserAuthentication);
    Assertions.assertEquals(PNR, result.getName());
  }  
  
  @Test
  public void testNoSsoDontReuse() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(false)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final Saml2UserAuthentication sso = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(sso.isReuseAuthentication()).thenReturn(false);
    Mockito.when(sso.getName()).thenReturn("SSO-USER");

    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(Instant.now().minus(Duration.ofMinutes(30)));
    Mockito.when(details.getAuthnContextUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(sso.getSaml2UserDetails()).thenReturn(details);

    Mockito.when(token.getUserAuthentication()).thenReturn(sso);

    final Authentication result = provider.authenticate(token);
    Assertions.assertTrue(result instanceof Saml2UserAuthentication);
    Assertions.assertEquals(PNR, result.getName());
  }
  
  @Test
  public void testNoSsoVoterSaysNo() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));
    
    provider.ssoVoters().clear();
    provider.ssoVoters().add((a, b, c) -> Vote.DENY);
    
    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(false)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final Saml2UserAuthentication sso = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(sso.isReuseAuthentication()).thenReturn(true);
    Mockito.when(sso.getName()).thenReturn("SSO-USER");

    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(Instant.now().minus(Duration.ofMinutes(30)));
    Mockito.when(details.getAuthnContextUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(sso.getSaml2UserDetails()).thenReturn(details);

    Mockito.when(token.getUserAuthentication()).thenReturn(sso);

    final Authentication result = provider.authenticate(token);
    Assertions.assertTrue(result instanceof Saml2UserAuthentication);
    Assertions.assertEquals(PNR, result.getName());
  }
  
  @Test
  public void testNoSsoVoterSaysDontKnow() {
    final TestProvider provider = new TestProvider(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));
    
    provider.ssoVoters().clear();
    provider.ssoVoters().add((a, b, c) -> Vote.DONT_KNOW);
    
    final Saml2UserAuthenticationInputToken token = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    final AuthenticationRequirements authnReqs = AuthenticationRequirementsBuilder.builder()
        .forceAuthn(false)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(token.getAuthnRequirements()).thenReturn(authnReqs);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("Log");
    Mockito.when(token.getAuthnRequestToken()).thenReturn(authnRequestToken);

    final Saml2UserAuthentication sso = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(sso.isReuseAuthentication()).thenReturn(true);
    Mockito.when(sso.getName()).thenReturn("SSO-USER");

    final Saml2UserDetails details = Mockito.mock(Saml2UserDetails.class);
    Mockito.when(details.getAuthnInstant()).thenReturn(Instant.now().minus(Duration.ofMinutes(30)));
    Mockito.when(details.getAuthnContextUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(sso.getSaml2UserDetails()).thenReturn(details);

    Mockito.when(token.getUserAuthentication()).thenReturn(sso);

    final Authentication result = provider.authenticate(token);
    Assertions.assertTrue(result instanceof Saml2UserAuthentication);
    Assertions.assertEquals(PNR, result.getName());
  }  

  private static class TestProvider extends AbstractUserAuthenticationProvider {

    private final List<String> supportedAuthnContextUris;
    private final List<String> entityCategories;

    public TestProvider(final List<String> supportedAuthnContextUris, final List<String> entityCategories) {
      this.supportedAuthnContextUris = supportedAuthnContextUris;
      this.entityCategories = entityCategories;
    }

    @Override
    public String getName() {
      return "test-provider";
    }

    @Override
    public List<String> getSupportedAuthnContextUris() {
      return this.supportedAuthnContextUris;
    }

    @Override
    public List<String> getEntityCategories() {
      return this.entityCategories;
    }

    @Override
    protected Authentication authenticate(
        final Saml2UserAuthenticationInputToken token, final List<String> authnContextUris)
        throws Saml2ErrorStatusException {

      final Saml2UserDetails details = new Saml2UserDetails(List.of(
          new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
              AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
              PNR),
          new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
              AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
              "Nina Greger")),
          AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
          LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
          Instant.now(), "127.0.0.1");

      return new Saml2UserAuthentication(details);
    }

  }

}
