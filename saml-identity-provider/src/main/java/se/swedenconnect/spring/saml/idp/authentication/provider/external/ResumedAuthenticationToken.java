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

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * A special purpose {@link Authentication} token that is used when the user returns to the authentication flow after
 * "external" authentication.
 *
 * @author Martin Lindström
 */
public class ResumedAuthenticationToken implements Authentication {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** Is set if the token represents a successful authentication. */
  private final Authentication authnToken;

  /** Is set if the token represents an authentication error. */
  private final Saml2ErrorStatusException error;

  /** Holds the corresponding authentication input token. */
  private Saml2UserAuthenticationInputToken authnInputToken;

  /** The servlet request for this token. */
  private transient HttpServletRequest servletRequest;

  /**
   * Constructor setting up the token to represent a successful authentication
   *
   * @param authnToken the authentication object
   */
  public ResumedAuthenticationToken(final Authentication authnToken) {
    this.authnToken = Objects.requireNonNull(authnToken, "authnToken must not be null");
    this.error = null;
  }

  /**
   * Constructor setting up the token to represent an authentication error.
   *
   * @param error the error
   */
  public ResumedAuthenticationToken(final Saml2ErrorStatusException error) {
    this.authnToken = null;
    this.error = Objects.requireNonNull(error, "error must not be null");
  }

  /**
   * Gets the authentication token the represents the user authentication (from the external process).
   *
   * @return an {@link Authentication} object or {@code null} if this object represents an authentication error
   */
  public Authentication getAuthnToken() {
    return this.authnToken;
  }

  /**
   * If this authentication object represents an authentication error the method returns this error.
   *
   * @return a {@link Saml2ErrorStatusException} or {@code null} if this object represents a successful authentication
   */
  public Saml2ErrorStatusException getError() {
    return this.error;
  }

  /**
   * Gets the {@link Saml2UserAuthenticationInputToken} for this operation.
   * 
   * @return a {@link Saml2UserAuthenticationInputToken}
   */
  public Saml2UserAuthenticationInputToken getAuthnInputToken() {
    return this.authnInputToken;
  }

  /**
   * Assigns the {@link Saml2UserAuthenticationInputToken} for this operation
   * 
   * @param authnInputToken a {@link Saml2UserAuthenticationInputToken}
   */
  public void setAuthnInputToken(final Saml2UserAuthenticationInputToken authnInputToken) {
    this.authnInputToken = authnInputToken;
  }

  /**
   * Gets the servlet request associated with this token.
   * 
   * @return the {@link HttpServletRequest} or {@code null} if not available
   */
  public HttpServletRequest getServletRequest() {
    return this.servletRequest;
  }

  /**
   * Assigns the servlet request to associate with this token
   * 
   * @param servletRequest a {@link HttpServletRequest}
   */
  public void setServletRequest(final HttpServletRequest servletRequest) {
    this.servletRequest = servletRequest;
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return Optional.ofNullable(this.authnToken)
        .map(Authentication::getName)
        .orElseGet(() -> "unknown");
  }

  /** {@inheritDoc} */
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Optional.ofNullable(this.authnToken)
        .map(Authentication::getAuthorities)
        .orElseGet(() -> Collections.emptyList());
  }

  /** {@inheritDoc} */
  @Override
  public Object getCredentials() {
    return Optional.ofNullable(this.authnToken)
        .map(Authentication::getCredentials)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public Object getDetails() {
    return Optional.ofNullable(this.authnToken)
        .map(Authentication::getDetails)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public Object getPrincipal() {
    return Optional.ofNullable(this.authnToken)
        .map(Authentication::getPrincipal)
        .orElseGet(() -> "saml-error");
  }

  /** {@inheritDoc} */
  @Override
  public boolean isAuthenticated() {
    return Optional.ofNullable(this.authnToken)
        .map(Authentication::isAuthenticated)
        .orElse(false);
  }

  /**
   * Must not be called, will throw {@link IllegalArgumentException}.
   */
  @Override
  public void setAuthenticated(final boolean isAuthenticated) throws IllegalArgumentException {
    throw new IllegalArgumentException(
        "setAuthenticated on " + this.getClass().getSimpleName() + " must not be called");
  }

}
