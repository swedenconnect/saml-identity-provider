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
package se.swedenconnect.spring.saml.idp.web.filters;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.attributes.ReleaseAllAttributeProducer;
import se.swedenconnect.spring.saml.idp.authentication.Saml2AssertionHandler;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseHandler;

/**
 * A {@link Filter} that intercept an SAML authentication request that has been verified and translated into a
 * {@link Saml2UserAuthenticationInputToken}.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class Saml2UserAuthenticationProcessingFilter extends OncePerRequestFilter {

  /** The authentication manager. */
  private final AuthenticationManager authenticationManager;

  /** The request matcher for the SSO endpoints. */
  private final RequestMatcher requestMatcher;

  /** The {@link Saml2ResponseHandler} to use when creating and sending the responses. */
  private final Saml2ResponseHandler responseHandler;

  /** The assertion handler responsible of creating {@link Assertion}s. */
  private final Saml2AssertionHandler assertionHandler;

  /**
   * Constructor.
   * 
   * @param authenticationManager the authentication manager
   * @param requestMatcher the request matcher
   * @param assertionHandler the assertion handler responsible of creating {@link Assertion}s
   * @param responseHandler the response handler
   */
  public Saml2UserAuthenticationProcessingFilter(final AuthenticationManager authenticationManager,
      final RequestMatcher requestMatcher,
      final Saml2AssertionHandler assertionHandler,
      final Saml2ResponseHandler responseHandler) {
    this.authenticationManager =
        Objects.requireNonNull(authenticationManager, "authenticationManager must not be null");
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.assertionHandler = Objects.requireNonNull(assertionHandler, "assertionHandler must not be null");
    this.responseHandler = Objects.requireNonNull(responseHandler, "responseHandler must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(
      final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    final Authentication authnInputToken = SecurityContextHolder.getContext().getAuthentication();
    if (authnInputToken != null && Saml2UserAuthenticationInputToken.class.isInstance(authnInputToken)) {
      final Authentication auth = this.authenticationManager.authenticate(authnInputToken);
      if (auth != null && Saml2UserAuthentication.class.isInstance(auth)) {
        final Saml2UserAuthentication authenticatedUser = Saml2UserAuthentication.class.cast(auth);
        
        authenticatedUser.setAuthnRequestToken(((Saml2UserAuthenticationInputToken) authnInputToken).getAuthnRequestToken());
        authenticatedUser.setAuthnRequirements(((Saml2UserAuthenticationInputToken) authnInputToken).getAuthnRequirements());
        
        final Assertion assertion = this.assertionHandler.buildAssertion(authenticatedUser, 
            new ReleaseAllAttributeProducer());
        
        this.responseHandler.sendSamlResponse(request, response, assertion);
        
        authenticatedUser.clearAuthnRequestToken();
        authenticatedUser.clearAuthnRequirements();
        
        final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authenticatedUser);
        SecurityContextHolder.setContext(securityContext);
        log.debug("Setting SecurityContextHolder authentication to {}", authenticatedUser.getClass().getSimpleName());
        
        return;        
      }
    }
    filterChain.doFilter(request, response);
    
  }

}
