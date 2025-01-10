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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.lang.NonNull;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.events.Saml2IdpEventPublisher;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseAttributes;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseBuilder;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseSender;

import java.io.IOException;
import java.util.Objects;

/**
 * A {@link Filter} responsible of sending SAML error response messages.
 *
 * @author Martin Lindström
 */
public class Saml2ErrorResponseProcessingFilter extends OncePerRequestFilter {

  /** The request matcher for the SSO endpoints. */
  private final RequestMatcher requestMatcher;

  /** The response builder. */
  private final Saml2ResponseBuilder responseBuilder;

  /** The response sender. */
  private final Saml2ResponseSender responseSender;

  /** The event publisher. */
  private final Saml2IdpEventPublisher eventPublisher;

  /** An analyzer for handling exceptions. */
  private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

  /**
   * Constructor.
   *
   * @param requestMatcher the request matcher
   * @param responseBuilder the {@link Saml2ResponseBuilder}
   * @param responseSender the {@link Saml2ResponseSender}
   * @param eventPublisher the system event publisher
   */
  public Saml2ErrorResponseProcessingFilter(final RequestMatcher requestMatcher,
      final Saml2ResponseBuilder responseBuilder, final Saml2ResponseSender responseSender,
      final Saml2IdpEventPublisher eventPublisher) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.responseBuilder = Objects.requireNonNull(responseBuilder, "responseBuilder must not be null");
    this.responseSender = Objects.requireNonNull(responseSender, "responseSender must not be null");
    this.eventPublisher = Objects.requireNonNull(eventPublisher, "eventPublisher must not be null");
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
    try {
      filterChain.doFilter(request, response);
    }
    catch (final IOException e) {
      throw e;
    }
    catch (final Exception e) {
      final Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(e);
      final Saml2ErrorStatusException samlException = (Saml2ErrorStatusException) this.throwableAnalyzer
          .getFirstThrowableOfType(Saml2ErrorStatusException.class, causeChain);

      if (samlException == null) {
        if (e instanceof final UnrecoverableSaml2IdpException unrecoverable) {
          this.eventPublisher.publishUnrecoverableSamlError(unrecoverable);
        }

        if (e instanceof ServletException) {
          throw (ServletException) e;
        }
        throw (RuntimeException) e;
      }
      if (response.isCommitted()) {
        throw new ServletException(
            "Unable to handle the Spring Security Exception because the response is already committed", e);
      }
      this.sendErrorResponse(request, response, samlException);
    }
  }

  /**
   * Sends a SAML error {@link Response} message.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param error the SAML error
   * @throws UnrecoverableSaml2IdpException for send errors
   */
  private void sendErrorResponse(
      final HttpServletRequest request, final HttpServletResponse response, final Saml2ErrorStatusException error)
      throws UnrecoverableSaml2IdpException {

    final Saml2ResponseAttributes responseAttributes = Saml2IdpContextHolder.getContext().getResponseAttributes();
    final Response samlResponse = this.responseBuilder.buildErrorResponse(responseAttributes, error);
    this.responseSender.send(
        request, response, responseAttributes.getDestination(), samlResponse, responseAttributes.getRelayState());
  }

  /**
   * Assigns a custom {@link ThrowableAnalyzer}.
   *
   * @param throwableAnalyzer a throwable analyzer
   */
  public void setThrowableAnalyzer(final ThrowableAnalyzer throwableAnalyzer) {
    Assert.notNull(throwableAnalyzer, "throwableAnalyzer must not be null");
    this.throwableAnalyzer = throwableAnalyzer;
  }

  /**
   * Default implementation of {@code ThrowableAnalyzer} which is capable of also unwrapping {@code ServletException}s.
   * Borrowed from {@code ExceptionTranslationFilter}.
   */
  private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {

    @Override
    protected void initExtractorMap() {
      super.initExtractorMap();
      this.registerExtractor(ServletException.class, (throwable) -> {
        ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
        return ((ServletException) throwable).getRootCause();
      });
    }

  }

}
