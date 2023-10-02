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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Test cases for SessionBasedExternalAuthenticationRepository.
 *
 * @author Martin Lindström
 */
public class SessionBasedExternalAuthenticationRepositoryTest {

  @Test
  public void testStartExternalAuthentication() {
    final RedirectForAuthenticationToken token = Mockito.mock(RedirectForAuthenticationToken.class);
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    repo.startExternalAuthentication(token, request);

    Mockito.verify(session, Mockito.times(1)).removeAttribute(Mockito.anyString());
    Mockito.verify(session, Mockito.times(1))
        .removeAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.RESULT_SESSION_KEY));

    Mockito.verify(session, Mockito.times(1)).setAttribute(
        Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY),
        Mockito.any(RedirectForAuthenticationToken.class));
    Mockito.verify(session, Mockito.times(1)).setAttribute(Mockito.anyString(), Mockito.any());
  }

  @Test
  public void testGetCompletedExternalAuthentication() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    final ResumedAuthenticationToken resumeToken = new ResumedAuthenticationToken(Mockito.mock(Authentication.class));
    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.RESULT_SESSION_KEY)))
        .thenReturn(resumeToken);

    final RedirectForAuthenticationToken inputToken = Mockito.mock(RedirectForAuthenticationToken.class);
    Mockito.when(inputToken.getAuthnInputToken()).thenReturn(Mockito.mock(Saml2UserAuthenticationInputToken.class));

    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY)))
        .thenReturn(inputToken);

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    final ResumedAuthenticationToken resume = repo.getCompletedExternalAuthentication(request);

    Assertions.assertNotNull(resume);
    Assertions.assertNotNull(resume.getAuthnInputToken());
  }

  @Test
  public void testGetCompletedExternalAuthenticationNoResumeToken() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.RESULT_SESSION_KEY)))
        .thenReturn(null);

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    Assertions.assertNull(repo.getCompletedExternalAuthentication(request));
  }

  @Test
  public void testGetCompletedExternalAuthenticationSessionError() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    final ResumedAuthenticationToken resumeToken = new ResumedAuthenticationToken(Mockito.mock(Authentication.class));
    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.RESULT_SESSION_KEY)))
        .thenReturn(resumeToken);

    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY)))
        .thenReturn(null);

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    Assertions.assertThrows(IllegalStateException.class, () -> repo.getCompletedExternalAuthentication(request));
  }

  @Test
  public void testGetExternalAuthenticationToken() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY)))
        .thenReturn(Mockito.mock(RedirectForAuthenticationToken.class));

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    Assertions.assertNotNull(repo.getExternalAuthenticationToken(request));
  }

  @Test
  public void testCompleteExternalAuthenticationSuccess() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY)))
        .thenReturn(Mockito.mock(RedirectForAuthenticationToken.class));

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    repo.completeExternalAuthentication(Mockito.mock(Authentication.class), request);

    Mockito.verify(session, Mockito.times(1)).setAttribute(
        Mockito.matches(SessionBasedExternalAuthenticationRepository.RESULT_SESSION_KEY),
        Mockito.any(ResumedAuthenticationToken.class));
  }

  @Test
  public void testCompleteExternalAuthenticationSuccessSessionError() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY)))
        .thenReturn(null);

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();

    Assertions.assertThrows(IllegalStateException.class,
        () -> repo.completeExternalAuthentication(Mockito.mock(Authentication.class), request));
  }

  @Test
  public void testCompleteExternalAuthenticationError() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY)))
        .thenReturn(Mockito.mock(RedirectForAuthenticationToken.class));

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    repo.completeExternalAuthentication(Mockito.mock(Saml2ErrorStatusException.class), request);

    Mockito.verify(session, Mockito.times(1)).setAttribute(
        Mockito.matches(SessionBasedExternalAuthenticationRepository.RESULT_SESSION_KEY),
        Mockito.any(ResumedAuthenticationToken.class));
  }

  @Test
  public void testCompleteExternalAuthenticationErrorSessionError() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession()).thenReturn(session);

    Mockito.when(session.getAttribute(Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY)))
        .thenReturn(null);

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    Assertions.assertThrows(IllegalStateException.class,
        () -> repo.completeExternalAuthentication(Mockito.mock(Saml2ErrorStatusException.class), request));
  }

  @Test
  public void testClear() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession(ArgumentMatchers.eq(false))).thenReturn(session);

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    repo.clear(request);

    Mockito.verify(session, Mockito.times(1)).removeAttribute(
        Mockito.matches(SessionBasedExternalAuthenticationRepository.INPUT_SESSION_KEY));
    Mockito.verify(session, Mockito.times(1)).removeAttribute(
        Mockito.matches(SessionBasedExternalAuthenticationRepository.RESULT_SESSION_KEY));
  }

  @Test
  public void testClearNoSession() {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final HttpSession session = Mockito.mock(HttpSession.class);
    Mockito.when(request.getSession(ArgumentMatchers.eq(false))).thenReturn(null);

    final SessionBasedExternalAuthenticationRepository repo = new SessionBasedExternalAuthenticationRepository();
    repo.clear(request);

    Mockito.verify(session, Mockito.times(0)).removeAttribute(Mockito.anyString());
  }

}
