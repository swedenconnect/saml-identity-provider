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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2UserAuthenticationProcessingFilter;

/**
 * A repository used by subclasses of {@link AbstractUserRedirectAuthenticationProvider} that needs to pick up the
 * tranferred {@link RedirectForAuthenticationToken} to serve as input for the user authentication. When the user
 * authentication is done, the {@link #completeExternalAuthentication(Authentication, HttpServletRequest)} or
 * {@link #completeExternalAuthentication(Saml2ErrorStatusException, HttpServletRequest)} method is invoked to save the
 * result.
 * <p>
 * Note that implementation of the {@link ExternalAuthenticatorTokenRepository} must used the same persistence strategy
 * as the {@link FilterAuthenticationTokenRepository} used by the {@link Saml2UserAuthenticationProcessingFilter}.
 * </p>
 * <p>
 * The persistence mechanism used will depend on the implementation, but most commonly the {@link HttpSession} will be
 * used to store the tokens.
 * </p>
 * 
 * @author Martin Lindström
 * @see FilterAuthenticationTokenRepository
 */
public interface ExternalAuthenticatorTokenRepository {

  /**
   * Gets the {@link RedirectForAuthenticationToken} that is the input for an external authentication process.
   * 
   * @param request the HTTP servlet request
   * @return the {@link RedirectForAuthenticationToken} or {@code null} if not present
   */
  RedirectForAuthenticationToken getExternalAuthenticationToken(final HttpServletRequest request);

  /**
   * Is invoken to commit the {@link Authentication} token that is the result from the external user authentication.
   * 
   * @param token the {@link Authentication} token
   * @param request the current HTTP request
   * @throws IllegalStateException if the corresponding {@link RedirectForAuthenticationToken} is not available in the
   *           repository
   */
  void completeExternalAuthentication(final Authentication token, final HttpServletRequest request)
      throws IllegalStateException;

  /**
   * Is invoken to commit the {@link Saml2ErrorStatusException} that is a description for a failed user authentication.
   * 
   * @param token the error
   * @param request the current HTTP request
   * @throws IllegalStateException if the corresponding {@link RedirectForAuthenticationToken} is not available in the
   *           repository
   */
  void completeExternalAuthentication(final Saml2ErrorStatusException error, final HttpServletRequest request)
      throws IllegalStateException;

}
