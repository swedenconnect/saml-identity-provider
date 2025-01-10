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
package se.swedenconnect.spring.saml.idp.authentication.provider.external;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Test cases for UserRedirectAuthenticationProvider.
 *
 * @author Martin Lindström
 */
public class UserRedirectAuthenticationProviderTest {

  @Test
  public void testAuthenticate() {
    final TestProvider provider = new TestProvider();

    final Authentication a = provider.authenticate(Mockito.mock(Saml2UserAuthenticationInputToken.class));
    Assertions.assertTrue(a instanceof UsernamePasswordAuthenticationToken);
  }

  @Test
  public void testAuthenticateResume() {
    final ResumedAuthenticationToken resume = Mockito.mock(ResumedAuthenticationToken.class);
    Mockito.when(resume.getAuthnToken()).thenReturn(Mockito.mock(UsernamePasswordAuthenticationToken.class));

    final TestProvider provider = new TestProvider();
    final Authentication a = provider.authenticate(resume);
    Assertions.assertTrue(a instanceof Saml2UserAuthentication);
  }

  @Test
  public void testAuthenticateResumeNotSupportedAuthToken() {
    final ResumedAuthenticationToken resume = Mockito.mock(ResumedAuthenticationToken.class);
    Mockito.when(resume.getAuthnToken()).thenReturn(Mockito.mock(PreAuthenticatedAuthenticationToken.class));

    final TestProvider provider = new TestProvider();
    Assertions.assertNull(provider.authenticate(resume));
  }

  @Test
  public void testAuthenticateBadType() {
    final TestProvider provider = new TestProvider();
    Assertions.assertNull(provider.authenticate(Mockito.mock(UsernamePasswordAuthenticationToken.class)));
  }

  @Test
  public void testSupports() {
    final TestProvider provider = new TestProvider();

    Assertions.assertTrue(provider.supports(Saml2UserAuthenticationInputToken.class));
    Assertions.assertTrue(provider.supports(ResumedAuthenticationToken.class));
    Assertions.assertFalse(provider.supports(Saml2AuthnRequestAuthenticationToken.class));
  }

  private static class TestProvider implements UserRedirectAuthenticationProvider {

    @Override
    public String getName() {
      return null;
    }

    @Override
    public Authentication authenticateUser(final Saml2UserAuthenticationInputToken token) throws Saml2ErrorStatusException {
      return Mockito.mock(UsernamePasswordAuthenticationToken.class);
    }

    @Override
    public List<String> getSupportedAuthnContextUris() {
      return null;
    }

    @Override
    public List<String> getEntityCategories() {
      return null;
    }

    @Override
    public Saml2UserAuthentication resumeAuthentication(final ResumedAuthenticationToken token)
        throws Saml2ErrorStatusException {
      return Mockito.mock(Saml2UserAuthentication.class);
    }

    @Override
    public boolean supportsUserAuthenticationToken(final Authentication authentication) {
      return authentication instanceof UsernamePasswordAuthenticationToken;
    }

    @Override
    public ExternalAuthenticatorTokenRepository getTokenRepository() {
      return null;
    }

    @Override
    public String getAuthnPath() {
      return null;
    }

    @Override
    public String getResumeAuthnPath() {
      return null;
    }

  }

}
