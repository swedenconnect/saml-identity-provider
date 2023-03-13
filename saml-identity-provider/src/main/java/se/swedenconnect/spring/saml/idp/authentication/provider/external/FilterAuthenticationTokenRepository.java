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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2UserAuthenticationProcessingFilter;

/**
 * Strategy for persisting a {@link RedirectForAuthenticationToken} and {@link ResumedAuthenticationToken} between
 * requests.
 * <p>
 * Used by {@link Saml2UserAuthenticationProcessingFilter} to obtain the tokens before invoking the
 * {@link AuthenticationManager}.
 * </p>
 * <p>
 * The persistence mechanism used will depend on the implementation, but most commonly the {@link HttpSession} will be
 * used to store the tokens.
 * </p>
 * 
 * @author Martin Lindström
 * @see ExternalAuthenticatorTokenRepository
 */
public interface FilterAuthenticationTokenRepository {

  /**
   * Starts an external authentication processs by storing the supplied {@link RedirectForAuthenticationToken}.
   * <p>
   * This happens when the {@link Saml2UserAuthenticationProcessingFilter} receives a
   * {@link RedirectForAuthenticationToken} from a call to {@link AuthenticationManager#authenticate(Authentication)}.
   * </p>
   * <p>
   * Any previously stored tokens are cleared.
   * </p>
   * 
   * @param token the {@link RedirectForAuthenticationToken}
   * @param request the HTTP servlet request
   */
  void startExternalAuthentication(final RedirectForAuthenticationToken token, final HttpServletRequest request);

  /**
   * Is invoked when the {@link Saml2UserAuthenticationProcessingFilter} receives a request on its "resume paths" (see
   * {@link Saml2UserAuthenticationProcessingFilter#setResumeAuthnRequestMatcher(org.springframework.security.web.util.matcher.RequestMatcher)}).
   * <p>
   * The method gets the {@link Authentication} object stored by the authenticator
   * ({@link ExternalAuthenticatorTokenRepository#completeExternalAuthentication(Authentication, HttpServletRequest)} or
   * {@link ExternalAuthenticatorTokenRepository#completeExternalAuthentication(Saml2ErrorStatusException, HttpServletRequest)})
   * and creates a {@link ResumedAuthenticationToken}.
   * </p>
   * 
   * @param request the HTTP request
   * @return a {@link ResumedAuthenticationToken} or {@code null} if no token exists
   * @throws IllegalStateException if a {@link ResumedAuthenticationToken} token exists, but no corresponding
   *           {@link RedirectForAuthenticationToken}
   */
  ResumedAuthenticationToken getCompletedExternalAuthentication(final HttpServletRequest request)
      throws IllegalStateException;

  /**
   * Clears the current external authentication.
   * 
   * @param request the HTTP servlet request
   */
  void clear(final HttpServletRequest request);

}
