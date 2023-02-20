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

import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseHandler;

/**
 * A {@link Filter} responsible of sending SAML error response messages.
 * 
 * @author Martin Lindström
 */
public class Saml2ErrorResponseProcessingFilter extends OncePerRequestFilter {

  /** The request matcher for the SSO endpoints. */
  private final RequestMatcher requestMatcher;

  /** The {@link Saml2ResponseHandler} to use when creating and sending the responses. */
  private final Saml2ResponseHandler responseHandler;

  /** An analyzer for handling exceptions. */
  private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

  /**
   * Constructor.
   * 
   * @param requestMatcher the request matcher
   * @param responseHandler the response handler
   */
  public Saml2ErrorResponseProcessingFilter(final RequestMatcher requestMatcher,      
      final Saml2ResponseHandler responseHandler) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
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
        if (e instanceof ServletException) {
          throw (ServletException) e;
        }
        if (e instanceof RuntimeException) {
          throw (RuntimeException) e;
        }
        throw new RuntimeException(e);
      }
      if (response.isCommitted()) {
        throw new ServletException(
            "Unable to handle the Spring Security Exception because the response is already committed", e);
      }
      this.responseHandler.sendErrorResponse(request, response, samlException);
    }
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
      registerExtractor(ServletException.class, (throwable) -> {
        ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
        return ((ServletException) throwable).getRootCause();
      });
    }

  }

}
