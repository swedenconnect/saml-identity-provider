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

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirementsBuilder;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * Abstract base class implementing the {@link UserRedirectAuthenticationProvider} interface.
 *
 * @author Martin Lindström
 */
public abstract class AbstractUserRedirectAuthenticationProvider extends AbstractUserAuthenticationProvider
    implements UserRedirectAuthenticationProvider {

  /** The path to where we redirect the user for authentication. */
  private final String authnPath;

  /**
   * The path that the authentication process uses to redirect the user back after a completed authentication
   * (successful or not).
   */
  private final String resumeAuthnPath;

  /** The token repository. */
  private ExternalAuthenticatorTokenRepository tokenRepository;

  /**
   * Constructor.
   *
   * @param authnPath the path to where we redirect the user for authentication
   * @param resumeAuthnPath the path that the authentication process uses to redirect the user back after a completed
   *          authentication
   */
  public AbstractUserRedirectAuthenticationProvider(final String authnPath, final String resumeAuthnPath) {
    this.authnPath = Optional.ofNullable(authnPath)
        .map(String::trim)
        .filter(p -> p.startsWith("/"))
        .orElseThrow(() -> new IllegalArgumentException("authnPath must be set and begin with a '/'"));
    this.resumeAuthnPath = Optional.ofNullable(resumeAuthnPath)
        .map(String::trim)
        .filter(p -> p.startsWith("/"))
        .orElseThrow(() -> new IllegalArgumentException("resumeAuthnPath must be set and begin with a '/'"));

    // Default to the session based repository ...
    this.tokenRepository = new SessionBasedExternalAuthenticationRepository();
  }

  /**
   * Will redirect to the configured authentication path ({@link #getAuthnPath()}) by returning a
   * {@link RedirectForAuthenticationToken}.
   */
  @Override
  protected Authentication authenticate(
      final Saml2UserAuthenticationInputToken token, final List<String> authnContextUris)
      throws Saml2ErrorStatusException {

    final Saml2UserAuthenticationInputToken updatedToken =
        new Saml2UserAuthenticationInputToken(token.getAuthnRequestToken(),
            AuthenticationRequirementsBuilder.builder(token.getAuthnRequirements())
                .authnContextRequirements(authnContextUris)
                .build());

    return new RedirectForAuthenticationToken(updatedToken, this.authnPath, this.resumeAuthnPath);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public ExternalAuthenticatorTokenRepository getTokenRepository() {
    return this.tokenRepository;
  }

  /**
   * Assigns the token repository to use (defaults to {@link SessionBasedExternalAuthenticationRepository}.
   *
   * @param tokenRepository the token repository
   */
  public void setTokenRepository(final ExternalAuthenticatorTokenRepository tokenRepository) {
    this.tokenRepository = Objects.requireNonNull(tokenRepository, "tokenRepository must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String getAuthnPath() {
    return this.authnPath;
  }

  /** {@inheritDoc} */
  @Override
  public String getResumeAuthnPath() {
    return this.resumeAuthnPath;
  }

}
