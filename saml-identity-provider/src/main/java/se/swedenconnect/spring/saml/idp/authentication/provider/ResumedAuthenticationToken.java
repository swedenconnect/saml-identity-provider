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
package se.swedenconnect.spring.saml.idp.authentication.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

public class ResumedAuthenticationToken implements Authentication {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  @Getter
  @Setter
  private Saml2UserAuthenticationInputToken authnInputToken;

  @Getter
  private Authentication authnToken;

  @Getter
  private Saml2ErrorStatusException error;

  @Getter
  @Setter
  private transient HttpServletRequest servletRequest;

  public ResumedAuthenticationToken(final Authentication authnToken) {
    this.authnToken = Objects.requireNonNull(authnToken, "authnToken must not be null");
  }

  public ResumedAuthenticationToken(final Saml2ErrorStatusException error) {
    this.error = Objects.requireNonNull(error, "error must not be null");
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
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    throw new IllegalArgumentException(
        "setAuthenticated on " + this.getClass().getSimpleName() + " must not be called");
  }

}
