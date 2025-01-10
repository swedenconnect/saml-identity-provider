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
package se.swedenconnect.spring.saml.idp.web.filters;

import java.io.IOException;
import java.util.Objects;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * A {@code Filter} that processes SAML {@code AuthnRequest} messages.
 */
@Slf4j
public class Saml2AuthnRequestProcessingFilter extends OncePerRequestFilter {

  /** The authentication manager. */
  private final AuthenticationManager authenticationManager;

  /** The request matcher for the SSO endpoints. */
  private final RequestMatcher requestMatcher;

  /** The {@link AuthenticationConverter} that builds an {@link Authentication} object from the request. */
  private final AuthenticationConverter authenticationConverter;

  /** The authentication success handler. */
  private AuthenticationSuccessHandler authenticationSuccessHandler = this::onAuthenticationSuccess;

  /**
   * Constructor.
   *
   * @param authenticationManager the authentication manager
   * @param requestMatcher the request matcher for matching incoming requests
   * @param authenticationConverter the authentication converter that converts a SAML {@code AuthnRequest} message
   */
  public Saml2AuthnRequestProcessingFilter(
      final AuthenticationManager authenticationManager,
      final RequestMatcher requestMatcher,
      final AuthenticationConverter authenticationConverter) {
    this.authenticationManager =
        Objects.requireNonNull(authenticationManager, "authenticationManager must not be null");
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.authenticationConverter =
        Objects.requireNonNull(authenticationConverter, "authenticationConverter must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(@NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response, @NonNull final FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    // Convert the incoming AuthnRequest ...
    //
    final Authentication authnRequest = this.authenticationConverter.convert(request);

    if (authnRequest instanceof Saml2AuthnRequestAuthenticationToken) {

      // Verify the authentication request and produce an input token for user authentication ...
      // Also check for possible SSO ...
      //
      final Authentication token = this.authenticationManager.authenticate(authnRequest);
      if (token instanceof Saml2UserAuthenticationInputToken) {

        // Check for possible authentication token that may be used for SSO.
        //
        final Authentication userAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (userAuthentication != null && userAuthentication.isAuthenticated()) {
          ((Saml2UserAuthenticationInputToken) token).setUserAuthentication(userAuthentication);
        }
      }
      this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, token);
    }
    filterChain.doFilter(request, response);
  }

  /**
   * Sets the {@link AuthenticationSuccessHandler} used for handling a successful client authentication and associating
   * the {@link Saml2AuthnRequestAuthenticationToken} to the {@link SecurityContext}.
   *
   * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling a successful client
   *          authentication
   */
  public void setAuthenticationSuccessHandler(final AuthenticationSuccessHandler authenticationSuccessHandler) {
    Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
    this.authenticationSuccessHandler = authenticationSuccessHandler;
  }

  /**
   * Default authentication success handler.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param authentication the authentication object
   */
  private void onAuthenticationSuccess(
      final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) {

    final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
    securityContext.setAuthentication(authentication);
    SecurityContextHolder.setContext(securityContext);
    log.debug("Setting SecurityContextHolder authentication to {}", authentication.getClass().getSimpleName());
  }

}
