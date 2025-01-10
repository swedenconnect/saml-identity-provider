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
package se.swedenconnect.spring.saml.idp.authentication.provider.external;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * An implementation of the {@link FilterAuthenticationTokenRepository} and {@link ExternalAuthenticatorTokenRepository}
 * interfaces that is session based.
 *
 * @author Martin Lindström
 */
public class SessionBasedExternalAuthenticationRepository
    implements FilterAuthenticationTokenRepository, ExternalAuthenticatorTokenRepository {

  /** The name of the session key where we store the {@link RedirectForAuthenticationToken}. */
  public static final String INPUT_SESSION_KEY =
      SessionBasedExternalAuthenticationRepository.class.getPackageName() + ".ExternalAuthnInput";

  /** The name of the session key where we store the {@link ResumedAuthenticationToken} (i.e., the result). **/
  public static final String RESULT_SESSION_KEY =
      SessionBasedExternalAuthenticationRepository.class.getPackageName() + ".ExternalAuthnResult";

  /** {@inheritDoc} */
  @Override
  public void startExternalAuthentication(
      final RedirectForAuthenticationToken token, final HttpServletRequest request) {
    Assert.notNull(token, "token must not be null");

    final HttpSession session = request.getSession();
    session.removeAttribute(RESULT_SESSION_KEY);
    session.setAttribute(INPUT_SESSION_KEY, token);
  }

  /** {@inheritDoc} */
  @Override
  public ResumedAuthenticationToken getCompletedExternalAuthentication(final HttpServletRequest request)
      throws IllegalStateException {
    final HttpSession session = request.getSession();
    final ResumedAuthenticationToken resultToken =
        (ResumedAuthenticationToken) session.getAttribute(RESULT_SESSION_KEY);
    if (resultToken == null) {
      return null;
    }
    final RedirectForAuthenticationToken inputToken =
        (RedirectForAuthenticationToken) session.getAttribute(INPUT_SESSION_KEY);
    if (inputToken == null) {
      throw new IllegalStateException("State error: Can not get authentication result - no authn input token exists");
    }
    resultToken.setAuthnInputToken(inputToken.getAuthnInputToken());
    resultToken.setServletRequest(request);
    return resultToken;
  }

  /** {@inheritDoc} */
  @Override
  public RedirectForAuthenticationToken getExternalAuthenticationToken(final HttpServletRequest request) {
    final HttpSession session = request.getSession();
    return (RedirectForAuthenticationToken) session.getAttribute(INPUT_SESSION_KEY);
  }

  /** {@inheritDoc} */
  @Override
  public void completeExternalAuthentication(final Authentication token, final HttpServletRequest request)
      throws IllegalStateException {
    Assert.notNull(token, "token must not be null");
    final HttpSession session = request.getSession();
    final RedirectForAuthenticationToken inputToken =
        (RedirectForAuthenticationToken) session.getAttribute(INPUT_SESSION_KEY);
    if (inputToken == null) {
      throw new IllegalStateException("Can not store authentication result - no authn input token exists");
    }
    final ResumedAuthenticationToken resultToken = new ResumedAuthenticationToken(token);
    session.setAttribute(RESULT_SESSION_KEY, resultToken);
  }

  /** {@inheritDoc} */
  @Override
  public void completeExternalAuthentication(final Saml2ErrorStatusException error, final HttpServletRequest request)
      throws IllegalStateException {
    Assert.notNull(error, "error must not be null");
    final HttpSession session = request.getSession();
    final RedirectForAuthenticationToken inputToken =
        (RedirectForAuthenticationToken) session.getAttribute(INPUT_SESSION_KEY);
    if (inputToken == null) {
      throw new IllegalStateException("Can not store authentication result - no authn input token exists");
    }
    final ResumedAuthenticationToken resultToken = new ResumedAuthenticationToken(error);
    session.setAttribute(RESULT_SESSION_KEY, resultToken);
  }

  /** {@inheritDoc} */
  @Override
  public void clear(final HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    if (session != null) {
      session.removeAttribute(RESULT_SESSION_KEY);
      session.removeAttribute(INPUT_SESSION_KEY);
    }
  }

}
