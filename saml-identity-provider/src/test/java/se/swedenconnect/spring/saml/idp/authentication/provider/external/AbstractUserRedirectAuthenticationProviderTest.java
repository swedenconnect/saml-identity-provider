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
package se.swedenconnect.spring.saml.idp.authentication.provider.external;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;

import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirementsBuilder;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Test cases for AbstractUserRedirectAuthenticationProvider.
 * 
 * @author Martin Lindström
 */
public class AbstractUserRedirectAuthenticationProviderTest {

  @Test
  public void testCtor() {
    Assertions.assertEquals("authnPath must be set and begin with a '/'",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new TestProvider(null, null);
        }).getMessage());
    Assertions.assertEquals("authnPath must be set and begin with a '/'",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new TestProvider("authn", null);
        }).getMessage());
    Assertions.assertEquals("resumeAuthnPath must be set and begin with a '/'",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new TestProvider("/authn", null);
        }).getMessage());
    Assertions.assertEquals("resumeAuthnPath must be set and begin with a '/'",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new TestProvider("/authn", "resume");
        }).getMessage());
    final TestProvider provider = new TestProvider("/authn", "/resume");
    Assertions.assertEquals("/authn", provider.getAuthnPath());
    Assertions.assertEquals("/resume", provider.getResumeAuthnPath());
  }
  
  @Test
  public void testAuthenticate() {
    final Saml2UserAuthenticationInputToken input = Mockito.mock(Saml2UserAuthenticationInputToken.class);
    Mockito.when(input.getAuthnRequestToken()).thenReturn(Mockito.mock(Saml2AuthnRequestAuthenticationToken.class));
    
    final AuthenticationRequirements reqs = AuthenticationRequirementsBuilder.builder()
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)
        .authnContextRequirement(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
        .build();
    Mockito.when(input.getAuthnRequirements()).thenReturn(reqs);
    
    final TestProvider provider = new TestProvider("/authn", "/resume");
    final Authentication auth = provider.authenticateTest(input, List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3));
    Assertions.assertTrue(auth instanceof RedirectForAuthenticationToken);
    final RedirectForAuthenticationToken token = (RedirectForAuthenticationToken) auth;
    Assertions.assertEquals("/authn", token.getAuthnPath());
    Assertions.assertEquals("/resume", token.getResumeAuthnPath());
    Assertions.assertEquals(List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3), 
        token.getAuthnInputToken().getAuthnRequirements().getAuthnContextRequirements());
    
  }

  private static class TestProvider extends AbstractUserRedirectAuthenticationProvider {

    public TestProvider(String authnPath, String resumeAuthnPath) {
      super(authnPath, resumeAuthnPath);
    }
    
    public Authentication authenticateTest(
        final Saml2UserAuthenticationInputToken token, final List<String> authnContextUris)
        throws Saml2ErrorStatusException {
      return this.authenticate(token, authnContextUris);
    }

    @Override
    public Saml2UserAuthentication resumeAuthentication(final ResumedAuthenticationToken token)
        throws Saml2ErrorStatusException {
      return null;
    }

    @Override
    public boolean supportsUserAuthenticationToken(Authentication authentication) {
      return true;
    }

    @Override
    public String getName() {
      return "test-provider";
    }

    @Override
    public List<String> getSupportedAuthnContextUris() {
      return Collections.emptyList();
    }

    @Override
    public List<String> getEntityCategories() {
      return Collections.emptyList();
    }

  }

}
