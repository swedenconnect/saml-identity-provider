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
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authentication.Saml2AssertionBuilder;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.AbstractRedirectUserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authentication.provider.ExternalAuthenticationRepository;
import se.swedenconnect.spring.saml.idp.authentication.provider.RedirectForAuthenticationToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.ResumedAuthenticationToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.SessionBasedExternalAuthenticationRepository;
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
@Slf4j
public class Saml2UserAuthenticationProcessingFilter extends OncePerRequestFilter {

  /** The authentication manager. */
  private final AuthenticationManager authenticationManager;

  /** The request matcher for the SSO endpoints. */
  private final RequestMatcher requestMatcher;

  /**
   * Optional request matcher for handling when the user agent is redirected back to the flow after that the user has
   * been authenticated using a {@link AbstractRedirectUserAuthenticationProvider}.
   */
  private RequestMatcher resumeAuthnRequestMatcher;

  /** The response builder. */
  private final Saml2ResponseBuilder responseBuilder;

  /** The response sender. */
  private final Saml2ResponseSender responseSender;

  /** The assertion handler responsible of creating {@link Assertion}s. */
  private final Saml2AssertionBuilder assertionHandler;

  // TODO
  private ExternalAuthenticationRepository externalAuthenticationRepository =
      new SessionBasedExternalAuthenticationRepository();

  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

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

    if (!this.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    Authentication inputToken;
    if (this.resumeAuthnRequestMatcher != null && this.resumeAuthnRequestMatcher.matches(request)) {

      inputToken = this.externalAuthenticationRepository.getCompletedExternalAuthentication(request);
      if (inputToken == null) {        
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_SESSION);
      }
      this.externalAuthenticationRepository.clear(request);
    }
    else {
      inputToken = SecurityContextHolder.getContext().getAuthentication();
      if (inputToken == null) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
            "Missing token - " + Saml2UserAuthenticationInputToken.class.getSimpleName());
      }
      if (!Saml2UserAuthenticationInputToken.class.isInstance(inputToken)) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
            "Expected token " + Saml2UserAuthenticationInputToken.class.getSimpleName()
                + " but was " + inputToken.getClass().getSimpleName());
      }
    }

    final Authentication auth;
    try {
      auth = this.authenticationManager.authenticate(inputToken);
    }
    catch (final ProviderNotFoundException e) {
      // If we could not find a authentication provider to handle the Saml2UserAuthenticationInputToken
      // it must mean that the implementation did not support the requested authentication context.
      // If it is another type of token this is a configuration error and we let the exception through.
      //
      if (Saml2UserAuthenticationInputToken.class.isInstance(inputToken)) {
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.NO_AUTHN_CONTEXT, "Authentication not possible", e);
      }
      else {
        throw e;
      }
    }

    // If a RedirectForAuthenticationToken is received, this is an order to initiate an "external authentication",
    // meaning that we should redirect the user agent.
    //
    if (RedirectForAuthenticationToken.class.isInstance(auth)) {
      final RedirectForAuthenticationToken redirectToken = RedirectForAuthenticationToken.class.cast(auth);
      this.externalAuthenticationRepository.startExternalAuthentication(redirectToken, request);

      log.info("Re-directing to {} for external authentication [{}]", redirectToken.getAuthnInputToken().getLogString());
      
      this.redirectStrategy.sendRedirect(request, response,
          redirectToken.getAuthnPath() + "?resumeUrl=" + redirectToken.getResumeAuthnPath());

      return;
    }
    
    // Otherwise we expect a Saml2UserAuthentication token ...
    //
    if (!Saml2UserAuthentication.class.isInstance(auth)) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
          String.format("Expected {} from authentication manager but got {}",
              Saml2UserAuthentication.class.getSimpleName(), auth.getClass().getSimpleName()));
    }
    final Saml2UserAuthentication authenticatedUser = Saml2UserAuthentication.class.cast(auth);

    // The assertion and response builders need information about the request ...
    //
    authenticatedUser.setAuthnRequestToken(getSamlInputToken(inputToken).getAuthnRequestToken());
    authenticatedUser.setAuthnRequirements(getSamlInputToken(inputToken).getAuthnRequirements());

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
  }
  
  private static Saml2UserAuthenticationInputToken getSamlInputToken(final Authentication auth) {
    if (auth instanceof Saml2UserAuthenticationInputToken) {
      return (Saml2UserAuthenticationInputToken) auth;
    }
    if (auth instanceof ResumedAuthenticationToken) {
      return ((ResumedAuthenticationToken) auth).getAuthnInputToken();
    }
    throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL);
  }

  /**
   * Assigns a request matcher for handling when the user agent is redirected back to the flow after that the user has
   * been authenticated using a {@link AbstractRedirectUserAuthenticationProvider}.
   * 
   * @param resumeAuthnRequestMatcher request matcher
   */
  public void setResumeAuthnRequestMatcher(final RequestMatcher resumeAuthnRequestMatcher) {
    this.resumeAuthnRequestMatcher = resumeAuthnRequestMatcher;
  }

  /**
   * Predicate telling whether any of this {@link Filter}s {@link RequestMatcher}s match the incoming request.
   * 
   * @param request the request to test
   * @return {@code true} for a match and {@code false} otherwise
   */
  private boolean matches(final HttpServletRequest request) {
    if (this.requestMatcher.matches(request)) {
      return true;
    }
    if (this.resumeAuthnRequestMatcher != null && this.resumeAuthnRequestMatcher.matches(request)) {
      return true;
    }
    return false;
  }

}
