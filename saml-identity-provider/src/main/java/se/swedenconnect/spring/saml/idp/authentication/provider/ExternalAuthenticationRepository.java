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
package se.swedenconnect.spring.saml.idp.authentication.provider;

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
 */
public interface ExternalAuthenticationRepository {

  /**
   * Starts an external authentication processs by storing the supplied {@link RedirectForAuthenticationToken}.
   * <p>
   * Any previously stored tokens are cleared.
   * </p>
   * 
   * @param token the {@link RedirectForAuthenticationToken}
   * @param request the HTTP servlet request
   */
  void startExternalAuthentication(final RedirectForAuthenticationToken token, final HttpServletRequest request);

  /**
   * Gets the {@link RedirectForAuthenticationToken} that is the input for an external authentication process.
   * 
   * @param request the HTTP servlet request
   * @return the {@link RedirectForAuthenticationToken} or {@code null} if not present
   */
  RedirectForAuthenticationToken getExternalAuthenticationToken(final HttpServletRequest request);

  void completeExternalAuthentication(final Authentication token, final HttpServletRequest request) throws IllegalStateException;

  void completeExternalAuthentication(final Saml2ErrorStatusException error, final HttpServletRequest request) throws IllegalStateException;

  ResumedAuthenticationToken getCompletedExternalAuthentication(final HttpServletRequest request) throws IllegalStateException;

  /**
   * Clears the current external authentication.
   * 
   * @param request the HTTP servlet request
   */
  void clear(final HttpServletRequest request);

}
