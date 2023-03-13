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

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2UserAuthenticationProcessingFilter;

/**
 * A {@code RedirectForAuthenticationToken} is used in the cases where a SAML {@link AuthenticationProvider} wants to
 * inform the filter {@link Saml2UserAuthenticationProcessingFilter} that the user agent should be re-directed to a
 * given path to perform the user authentication.
 * 
 * @author Martin Lindström
 * @see AbstractUserRedirectAuthenticationProvider
 */
public class RedirectForAuthenticationToken implements Authentication {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The authentication input token. */
  private Saml2UserAuthenticationInputToken authnInputToken;

  /** The path to where we redirect the user for authentication. */
  private String authnPath;

  /**
   * The path that the authenticator uses to redirect the user back after a completed authentication (successful or
   * not).
   */
  private String resumeAuthnPath;

  /**
   * Constructor.
   * 
   * @param authnInputToken the authentication input token
   * @param authnPath the path to where we redirect the user for authentication
   * @param resumeAuthnPath the path that the authenticator uses to redirect the user back after a completed
   *          authentication (may be null)
   */
  public RedirectForAuthenticationToken(final Saml2UserAuthenticationInputToken authnInputToken,
      final String authnPath, final String resumeAuthnPath) {
    this.authnInputToken = Objects.requireNonNull(authnInputToken, "authnInputToken must not be null");
    this.authnPath = Optional.ofNullable(authnPath)
        .map(String::trim)
        .filter(p -> p.startsWith("/"))
        .orElseThrow(() -> new IllegalArgumentException("authnPath must be set and begin with a '/'"));
    this.resumeAuthnPath = Optional.ofNullable(resumeAuthnPath)
        .map(String::trim)
        .filter(p -> p.startsWith("/"))
        .orElseThrow(() -> new IllegalArgumentException("resumeAuthnPath must be set and begin with a '/'"));
  }

  /**
   * Gets the authentication input token.
   * 
   * @return a {@link Saml2UserAuthenticationInputToken}
   */
  public Saml2UserAuthenticationInputToken getAuthnInputToken() {
    return this.authnInputToken;
  }

  /**
   * Gets the path to where we redirect the user for authentication.
   * 
   * @return the path to where we redirect the user for authentication
   */
  public String getAuthnPath() {
    return this.authnPath;
  }

  /**
   * Gets the path that the authenticator uses to redirect the user back after a completed authentication.
   * 
   * @return the return/resume path
   */
  public String getResumeAuthnPath() {
    return this.resumeAuthnPath;
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return this.authnInputToken.getName();
  }

  /** {@inheritDoc} */
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Collections.emptyList();
  }

  /** {@inheritDoc} */
  @Override
  public Object getCredentials() {
    return this.authnInputToken.getCredentials();
  }

  /** {@inheritDoc} */
  @Override
  public Object getDetails() {
    return this.authnInputToken.getDetails();
  }

  /** {@inheritDoc} */
  @Override
  public Object getPrincipal() {
    return this.authnInputToken.getPrincipal();
  }

  /** {@inheritDoc} */
  @Override
  public boolean isAuthenticated() {
    return false;
  }

  /**
   * Must not be called, will throw {@link IllegalArgumentException}.
   */
  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    throw new IllegalArgumentException(
        "setAuthenticated on " + this.getClass().getSimpleName() + " must not be called");
  }

}
