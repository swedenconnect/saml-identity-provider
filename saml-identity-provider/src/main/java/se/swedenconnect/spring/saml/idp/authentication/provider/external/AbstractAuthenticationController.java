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

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * A helper class that {@link Controller}s that implement "external user authentication" may inherit from.
 *
 * @param <T> the type of the authentication provider
 *
 * @author Martin Lindström
 */
public abstract class AbstractAuthenticationController<T extends UserRedirectAuthenticationProvider> {

  /**
   * Gets the {@link RedirectForAuthenticationToken} that is the input for the "external authentication" process.
   *
   * @param request the HTTP servlet request
   * @return a {@link RedirectForAuthenticationToken}
   * @throws UnrecoverableSaml2IdpException if no token is available
   */
  protected RedirectForAuthenticationToken getInputToken(final HttpServletRequest request)
      throws UnrecoverableSaml2IdpException {
    return Optional.ofNullable(this.getProvider().getTokenRepository().getExternalAuthenticationToken(request))
        .orElseThrow(() -> new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_SESSION,
            "No input token available", null));
  }

  /**
   * Utility method that saves the authentication result in the {@link ExternalAuthenticatorTokenRepository} of the
   * provider and redirects the user back to the SAML IdP Spring Security flow
   * ({@link UserRedirectAuthenticationProvider#getResumeAuthnPath()}).
   *
   * @param request the HTTP servlet request
   * @param authentication the authentication object
   * @return a {@link ModelAndView} that redirects the user back to the configured resume path
   */
  protected ModelAndView complete(final HttpServletRequest request, final Authentication authentication) {
    final T provider = this.getProvider();
    provider.getTokenRepository().completeExternalAuthentication(authentication, request);
    return new ModelAndView("redirect:" + provider.getResumeAuthnPath());
  }

  /**
   * Utility method that saves the authentication error in the {@link ExternalAuthenticatorTokenRepository} of the
   * provider and redirects the user back to the SAML IdP Spring Security flow
   * ({@link UserRedirectAuthenticationProvider#getResumeAuthnPath()}).
   *
   * @param request the HTTP servlet request
   * @param error the authentication error
   * @return a {@link ModelAndView} that redirects the user back to the configured resume path
   */
  protected ModelAndView complete(final HttpServletRequest request, final Saml2ErrorStatusException error) {
    final T provider = this.getProvider();
    provider.getTokenRepository().completeExternalAuthentication(error, request);
    return new ModelAndView("redirect:" + provider.getResumeAuthnPath());
  }

  /**
   * Maps to {@code complete(request, new Saml2ErrorStatusException(Saml2ErrorStatus.CANCEL))}.
   *
   * @param request the HTTP servlet request
   * @return a {@link ModelAndView} that redirects the user back to the configured resume path
   */
  protected ModelAndView cancel(final HttpServletRequest request) {
    return this.complete(request, new Saml2ErrorStatusException(Saml2ErrorStatus.CANCEL));
  }

  /**
   * Gets the {@link UserRedirectAuthenticationProvider} for this type of user authentication.
   *
   * @return the user authentication provider
   */
  protected abstract T getProvider();

}
