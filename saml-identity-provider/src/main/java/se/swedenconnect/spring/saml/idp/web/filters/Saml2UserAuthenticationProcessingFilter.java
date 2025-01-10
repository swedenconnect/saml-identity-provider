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
import java.util.Optional;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authentication.PostAuthenticationProcessor;
import se.swedenconnect.spring.saml.idp.authentication.Saml2AssertionBuilder;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.AbstractUserRedirectAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.ExternalAuthenticatorTokenRepository;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.FilterAuthenticationTokenRepository;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.RedirectForAuthenticationToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.ResumedAuthenticationToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.SessionBasedExternalAuthenticationRepository;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.events.Saml2IdpEventPublisher;
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

  /** Session key where we store response attributes. */
  public static final String RESPONSE_ATTRIBUTES_SESSION_KEY =
      Saml2UserAuthenticationProcessingFilter.class.getPackageName() + ".ResponseAttributes";

  /** The authentication manager. */
  private final AuthenticationManager authenticationManager;

  /** The request matcher for the SSO endpoints. */
  private final RequestMatcher requestMatcher;

  /**
   * Optional request matcher for handling when the user agent is redirected back to the flow after that the user has
   * been authenticated using a {@link AbstractUserRedirectAuthenticationProvider}.
   */
  private RequestMatcher resumeAuthnRequestMatcher;

  /** The response builder. */
  private final Saml2ResponseBuilder responseBuilder;

  /** The response sender. */
  private final Saml2ResponseSender responseSender;

  /** The {@link PostAuthenticationProcessor} for checks and modification after a completed authentication. */
  private final PostAuthenticationProcessor postAuthenticationProcessor;

  /** The assertion handler responsible for creating {@link Assertion}s. */
  private final Saml2AssertionBuilder assertionHandler;

  /** The event publisher. */
  private final Saml2IdpEventPublisher eventPublisher;

  /** Repository storing authentication objects used for external authentication. */
  private FilterAuthenticationTokenRepository authenticationTokenRepository =
      new SessionBasedExternalAuthenticationRepository();

  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  /**
   * Constructor.
   *
   * @param authenticationManager the authentication manager
   * @param requestMatcher the request matcher
   * @param postAuthenticationProcessor processor for checking the authentication token after the provider has
   *          authenticated the user
   * @param assertionHandler the assertion handler responsible for creating {@link Assertion}s
   * @param responseBuilder the {@link Saml2ResponseBuilder}
   * @param responseSender the {@link Saml2ResponseSender}
   * @param eventPublisher the event publisher
   */
  public Saml2UserAuthenticationProcessingFilter(final AuthenticationManager authenticationManager,
      final RequestMatcher requestMatcher,
      final PostAuthenticationProcessor postAuthenticationProcessor,
      final Saml2AssertionBuilder assertionHandler,
      final Saml2ResponseBuilder responseBuilder,
      final Saml2ResponseSender responseSender,
      final Saml2IdpEventPublisher eventPublisher) {
    this.authenticationManager =
        Objects.requireNonNull(authenticationManager, "authenticationManager must not be null");
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.postAuthenticationProcessor =
        Objects.requireNonNull(postAuthenticationProcessor, "postAuthenticationProcessor must not be null");
    this.assertionHandler = Objects.requireNonNull(assertionHandler, "assertionHandler must not be null");
    this.responseBuilder = Objects.requireNonNull(responseBuilder, "responseBuilder must not be null");
    this.responseSender = Objects.requireNonNull(responseSender, "responseSender must not be null");
    this.eventPublisher = Objects.requireNonNull(eventPublisher, "eventPublisher must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(@NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response, @NonNull final FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    final Authentication inputToken;
    if (this.resumeAuthnRequestMatcher != null && this.resumeAuthnRequestMatcher.matches(request)) {

      // OK, the user returns to the flow after an external authentication.
      // Restore the response attributes ...
      //
      final HttpSession session = request.getSession();
      final Saml2ResponseAttributes responseAttributes =
          (Saml2ResponseAttributes) session.getAttribute(RESPONSE_ATTRIBUTES_SESSION_KEY);
      if (responseAttributes == null) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_SESSION, null);
      }
      session.removeAttribute(RESPONSE_ATTRIBUTES_SESSION_KEY);

      inputToken = this.authenticationTokenRepository.getCompletedExternalAuthentication(request);
      this.authenticationTokenRepository.clear(request);
      if (inputToken == null) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_SESSION,
            new UnrecoverableSaml2IdpException.TraceAuthentication(responseAttributes.getInResponseTo(),
                Optional.ofNullable(responseAttributes.getPeerMetadata()).map(EntityDescriptor::getEntityID)
                    .orElse(null)));
      }

      final ResumedAuthenticationToken resumeToken = (ResumedAuthenticationToken) inputToken;

      // Make sure we got the correct response attributes object ...
      //
      final String currentAuthnRequestID = Optional.ofNullable(resumeToken.getAuthnInputToken())
          .map(Saml2UserAuthenticationInputToken::getAuthnRequestToken)
          .map(Saml2AuthnRequestAuthenticationToken::getAuthnRequest)
          .map(AuthnRequest::getID)
          .orElseThrow(() -> new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_SESSION,
              "Failed to get information about authentication request", resumeToken));

      if (!Objects.equals(currentAuthnRequestID, responseAttributes.getInResponseTo())) {
        final String msg = "State error: Saved response attributes does not match information about current request";
        log.error("{} [{}]", msg, Optional.ofNullable(resumeToken.getAuthnInputToken())
            .map(Saml2UserAuthenticationInputToken::getLogString)
            .orElse("-"));
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_SESSION, msg, resumeToken);
      }
      Saml2IdpContextHolder.getContext().getResponseAttributes().copyInto(responseAttributes);

      // Handle error and let the error response processing filter send the error response ...
      //
      if (resumeToken.getError() != null) {
        log.info("Error from external authentication: {} [{}]", resumeToken.getError(),
            Optional.ofNullable(resumeToken.getAuthnInputToken())
                .map(Saml2UserAuthenticationInputToken::getLogString)
                .orElse("-"));
        throw resumeToken.getError();
      }
    }
    else {
      inputToken = SecurityContextHolder.getContext().getAuthentication();
      if (inputToken == null) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
            "Missing token - " + Saml2UserAuthenticationInputToken.class.getSimpleName(), null);
      }
      if (!(inputToken instanceof Saml2UserAuthenticationInputToken)) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
            "Expected token " + Saml2UserAuthenticationInputToken.class.getSimpleName()
                + " but was " + inputToken.getClass().getSimpleName(), null);
      }

      this.eventPublisher.publishBeforeUserAuthenticated((Saml2UserAuthenticationInputToken) inputToken);
    }

    final Authentication auth;
    try {
      auth = this.authenticationManager.authenticate(inputToken);
    }
    catch (final ProviderNotFoundException e) {
      // If we could not find na authentication provider to handle the Saml2UserAuthenticationInputToken
      // it must mean that the implementation did not support the requested authentication context.
      // If it is another type of token this is a configuration error, and we let the exception through.
      //
      if (inputToken instanceof Saml2UserAuthenticationInputToken) {
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.NO_AUTHN_CONTEXT, "Authentication not possible", e);
      }
      else {
        throw e;
      }
    }

    // If a RedirectForAuthenticationToken is received, this is an order to initiate an "external authentication",
    // meaning that we should redirect the user agent.
    //
    if (auth instanceof final RedirectForAuthenticationToken redirectToken) {
      this.authenticationTokenRepository.startExternalAuthentication(redirectToken, request);

      log.info("Re-directing to {} for external authentication [{}]",
          redirectToken.getAuthnPath(), redirectToken.getAuthnInputToken().getLogString());

      // Save the response attributes in the session so that we know how to send back a response
      // when the user returns to the flow.
      //
      request.getSession().setAttribute(RESPONSE_ATTRIBUTES_SESSION_KEY,
          Saml2IdpContextHolder.getContext().getResponseAttributes());

      this.redirectStrategy.sendRedirect(request, response, redirectToken.getAuthnPath());
      return;
    }

    // Otherwise we expect a Saml2UserAuthentication token ...
    //
    if (!(auth instanceof final Saml2UserAuthentication authenticatedUser)) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
          String.format("Expected %s from authentication manager but got %s",
              Saml2UserAuthentication.class.getSimpleName(), auth.getClass().getSimpleName()), null);
    }

    // The assertion and response builders need information about the request ...
    //
    authenticatedUser.setAuthnRequestToken(getSamlInputToken(inputToken).getAuthnRequestToken());
    authenticatedUser.setAuthnRequirements(getSamlInputToken(inputToken).getAuthnRequirements());

    // Publish the event that indicates that the user has been authenticated ...
    //
    this.eventPublisher.publishUserAuthenticated(authenticatedUser);

    // Apply the post processor ...
    //
    this.postAuthenticationProcessor.process(authenticatedUser);

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
    throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, null);
  }

  /**
   * Assigns a request matcher for handling when the user agent is redirected back to the flow after that the user has
   * been authenticated using a {@link AbstractUserRedirectAuthenticationProvider}.
   *
   * @param resumeAuthnRequestMatcher request matcher
   */
  public void setResumeAuthnRequestMatcher(final RequestMatcher resumeAuthnRequestMatcher) {
    this.resumeAuthnRequestMatcher = resumeAuthnRequestMatcher;
  }

  /**
   * Assigns a {@link FilterAuthenticationTokenRepository} instance for storing {@link Authentication} objects when
   * external authentication is used. The default is {@link SessionBasedExternalAuthenticationRepository}.
   * <p>
   * Note: Ensure that the {@link ExternalAuthenticatorTokenRepository} assigned to the
   * {@link AbstractUserRedirectAuthenticationProvider} is using the same persistence strategy as the assigned
   * repository bean.
   * </p>
   *
   * @param authenticationTokenRepository token repository
   */
  public void setAuthenticationTokenRepository(
      final FilterAuthenticationTokenRepository authenticationTokenRepository) {
    this.authenticationTokenRepository =
        Objects.requireNonNull(authenticationTokenRepository, "authenticationTokenRepository must not be null");
  }

  /**
   * Predicate telling whether any of this {@link Filter}s {@link RequestMatcher}s match the incoming request.
   *
   * @param request the request to test
   * @return {@code true} for a match and {@code false} otherwise
   */
  private boolean matches(final HttpServletRequest request) {
    return this.requestMatcher.matches(request)
        || (this.resumeAuthnRequestMatcher != null && this.resumeAuthnRequestMatcher.matches(request));
  }

}
