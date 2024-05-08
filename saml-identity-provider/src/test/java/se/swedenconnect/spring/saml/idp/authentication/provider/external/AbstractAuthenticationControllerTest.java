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
package se.swedenconnect.spring.saml.idp.authentication.provider.external;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * Test cases for AbstractAuthenticationController.
 *
 * @author Martin Lindström
 */
public class AbstractAuthenticationControllerTest extends OpenSamlTestBase {

  @Test
  public void testSuccess() {
    final TestProvider provider = new TestProvider("/authn", "/resume");
    final TestRepo repo = new TestRepo(Mockito.mock(RedirectForAuthenticationToken.class));
    provider.setTokenRepository(repo);

    final TestController controller = new TestController(provider);

    final ModelAndView mav = controller.authenticate(
        Mockito.mock(HttpServletRequest.class), Mockito.mock(HttpServletResponse.class), true, false);

    Assertions.assertEquals("redirect:/resume", mav.getViewName());
    Assertions.assertNotNull(repo.getAuthentication());
    Assertions.assertNull(repo.getError());
  }

  @Test
  public void testCancel() {
    final TestProvider provider = new TestProvider("/authn", "/resume");
    final TestRepo repo = new TestRepo(Mockito.mock(RedirectForAuthenticationToken.class));
    provider.setTokenRepository(repo);

    final TestController controller = new TestController(provider);

    final ModelAndView mav = controller.authenticate(
        Mockito.mock(HttpServletRequest.class), Mockito.mock(HttpServletResponse.class), true, true);

    Assertions.assertEquals("redirect:/resume", mav.getViewName());
    Assertions.assertNull(repo.getAuthentication());
    Assertions.assertNotNull(repo.getError());
    Assertions.assertEquals(Saml2ErrorStatus.CANCEL.getSubStatusCode(),
        repo.getError().getStatus().getStatusCode().getStatusCode().getValue());
  }

  @Test
  public void testError() {
    final TestProvider provider = new TestProvider("/authn", "/resume");
    final TestRepo repo = new TestRepo(Mockito.mock(RedirectForAuthenticationToken.class));
    provider.setTokenRepository(repo);

    final TestController controller = new TestController(provider);

    final ModelAndView mav = controller.authenticate(
        Mockito.mock(HttpServletRequest.class), Mockito.mock(HttpServletResponse.class), false, false);

    Assertions.assertEquals("redirect:/resume", mav.getViewName());
    Assertions.assertNull(repo.getAuthentication());
    Assertions.assertNotNull(repo.getError());
    Assertions.assertEquals(Saml2ErrorStatus.AUTHN_FAILED.getSubStatusCode(),
        repo.getError().getStatus().getStatusCode().getStatusCode().getValue());
  }

  @Test
  public void testNoSession() {
    final TestProvider provider = new TestProvider("/authn", "/resume");
    final TestRepo repo = new TestRepo(null);
    provider.setTokenRepository(repo);

    final TestController controller = new TestController(provider);

    Assertions.assertEquals(UnrecoverableSaml2IdpError.INVALID_SESSION,
        Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> {
          controller.authenticate(
              Mockito.mock(HttpServletRequest.class), Mockito.mock(HttpServletResponse.class), true, false);
        }).getError());

  }

  private static class TestRepo implements ExternalAuthenticatorTokenRepository {

    private final RedirectForAuthenticationToken token;

    @Getter
    private Authentication authentication;

    @Getter
    private Saml2ErrorStatusException error;

    public TestRepo(final RedirectForAuthenticationToken token) {
      this.token = token;
    }

    @Override
    public RedirectForAuthenticationToken getExternalAuthenticationToken(HttpServletRequest request) {
      return token;
    }

    @Override
    public void completeExternalAuthentication(Authentication token, HttpServletRequest request)
        throws IllegalStateException {
      this.authentication = token;
    }

    @Override
    public void completeExternalAuthentication(Saml2ErrorStatusException error, HttpServletRequest request)
        throws IllegalStateException {
      this.error = error;
    }

  }

  private static class TestController extends AbstractAuthenticationController<TestProvider> {

    private final TestProvider provider;

    public TestController(final TestProvider provider) {
      this.provider = provider;
    }

    public ModelAndView authenticate(final HttpServletRequest request, final HttpServletResponse response,
        final boolean success, final boolean cancel) {

      this.getInputToken(request).getAuthnInputToken();

      if (!success) {
        return this.complete(request, new Saml2ErrorStatusException(Saml2ErrorStatus.AUTHN_FAILED));
      }
      else if (cancel) {
        return this.cancel(request);
      }
      else {
        return this.complete(request, Mockito.mock(Authentication.class));
      }
    }

    @Override
    protected TestProvider getProvider() {
      return this.provider;
    }

  }

  private static class TestProvider extends AbstractUserRedirectAuthenticationProvider {

    public TestProvider(final String authnPath, final String resumeAuthnPath) {
      super(authnPath, resumeAuthnPath);
    }

    @Override
    public Saml2UserAuthentication resumeAuthentication(ResumedAuthenticationToken token)
        throws Saml2ErrorStatusException {
      return null;
    }

    @Override
    public boolean supportsUserAuthenticationToken(Authentication authentication) {
      return false;
    }

    @Override
    public String getName() {
      return "test-provider";
    }

    @Override
    public List<String> getSupportedAuthnContextUris() {
      return null;
    }

    @Override
    public List<String> getEntityCategories() {
      return null;
    }

  }

}
