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
import org.opensaml.saml.saml2.core.Response;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.saml.idp.authentication.Saml2AssertionBuilder;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseAttributes;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseBuilder;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseSender;

/**
 * A {@link Filter} that intercept an SAML authentication request that has been verified and translated into a
 * {@link Saml2UserAuthenticationInputToken}.
 * 
 * @author Martin Lindström
 */
public class Saml2UserAuthenticationProcessingFilter extends OncePerRequestFilter {

  /** The authentication manager. */
  private final AuthenticationManager authenticationManager;

  /** The request matcher for the SSO endpoints. */
  private final RequestMatcher requestMatcher;

  /** The response builder. */
  private final Saml2ResponseBuilder responseBuilder;

  /** The response sender. */
  private final Saml2ResponseSender responseSender;

  /** The assertion handler responsible of creating {@link Assertion}s. */
  private final Saml2AssertionBuilder assertionHandler;

  /**
   * Constructor.
   * 
   * @param authenticationManager the authentication manager
   * @param requestMatcher the request matcher
   * @param assertionHandler the assertion handler responsible of creating {@link Assertion}s
   * @param responseBuilder the {@link Saml2ResponseBuilder}
   * @param responseSender the {@link Saml2ResponseSender}
   */
  public Saml2UserAuthenticationProcessingFilter(final AuthenticationManager authenticationManager,
      final RequestMatcher requestMatcher,
      final Saml2AssertionBuilder assertionHandler,
      final Saml2ResponseBuilder responseBuilder,
      final Saml2ResponseSender responseSender) {
    this.authenticationManager =
        Objects.requireNonNull(authenticationManager, "authenticationManager must not be null");
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.assertionHandler = Objects.requireNonNull(assertionHandler, "assertionHandler must not be null");
    this.responseBuilder = Objects.requireNonNull(responseBuilder, "responseBuilder must not be null");
    this.responseSender = Objects.requireNonNull(responseSender, "responseSender must not be null");
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
      if (auth == null) {
        // TODO: direct to error handler instead ...
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.NO_AUTHN_CONTEXT);
      }
      if (!Saml2UserAuthentication.class.isInstance(auth)) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
            String.format("Expected {} from authentication manager but got {}",
                Saml2UserAuthentication.class.getSimpleName(), auth.getClass().getSimpleName()));
      }

      final Saml2UserAuthentication authenticatedUser = Saml2UserAuthentication.class.cast(auth);

      // The assertion and response builders need information about the request ...
      //
      authenticatedUser
          .setAuthnRequestToken(((Saml2UserAuthenticationInputToken) authnInputToken).getAuthnRequestToken());
      authenticatedUser
          .setAuthnRequirements(((Saml2UserAuthenticationInputToken) authnInputToken).getAuthnRequirements());

      // Build assertion and response ...
      //
      final Assertion assertion = this.assertionHandler.buildAssertion(authenticatedUser);
      final Saml2ResponseAttributes responseAttributes = Saml2IdpContextHolder.getContext().getResponseAttributes();
      final Response samlResponse = this.responseBuilder.buildResponse(responseAttributes, assertion);

      // Send response ...
      //
      this.responseSender.send(
          request, response, responseAttributes.getDestination(), samlResponse, responseAttributes.getRelayState());

      authenticatedUser.clearAuthnRequestToken();
      authenticatedUser.clearAuthnRequirements();

      // Should we save the authentication for future use?
      //
      final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
      if (authenticatedUser.isReuseAuthentication()) {
        securityContext.setAuthentication(authenticatedUser);
      }
      SecurityContextHolder.setContext(securityContext);

      return;
    }

    // TODO: error
    filterChain.doFilter(request, response);

  }

}
