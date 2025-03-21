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
package se.swedenconnect.spring.saml.idp.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

import java.io.Serial;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

/**
 * An {@link Authentication} class that represents the input to a user authentication process for a SAML IdP.
 *
 * @author Martin Lindström
 */
public class Saml2UserAuthenticationInputToken extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The authentication request token. */
  private final Saml2AuthnRequestAuthenticationToken authnRequestToken;

  /** The authentication requirements. */
  private final AuthenticationRequirements authnRequirements;

  /** The user authentication object - used in SSO cases. */
  private Authentication userAuthentication;

  /** The UI info - may be useful for IdP UI. */
  private transient Saml2ServiceProviderUiInfo uiInfo;

  /**
   * Constructor.
   *
   * @param authnRequestToken the authentication request token
   * @param authnRequirements the authentication requirements
   */
  public Saml2UserAuthenticationInputToken(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken,
      final AuthenticationRequirements authnRequirements) {

    super(Collections.emptyList());
    this.authnRequestToken = Objects.requireNonNull(authnRequestToken, "authnRequestToken must not be null");
    this.authnRequirements = Objects.requireNonNull(authnRequirements, "authnRequirements must not be null");
    this.setAuthenticated(this.authnRequestToken.isAuthenticated());
  }

  /**
   * Gets the authentication request token.
   *
   * @return the authentication request token
   */
  public Saml2AuthnRequestAuthenticationToken getAuthnRequestToken() {
    return this.authnRequestToken;
  }

  /**
   * Gets the authentication requirements.
   *
   * @return the authentication requirements
   */
  public AuthenticationRequirements getAuthnRequirements() {
    return this.authnRequirements;
  }

  /**
   * If an {@link Authentication} object is available (from the {@link SecurityContextHolder}) when entering the SAML
   * flow, this object is made available to the authentication process that will determine if this authentication object
   * may be used for SSO.
   *
   * @return the {@link Authentication} object from a previous authentication, or {@code null} if not available
   */
  public Authentication getUserAuthentication() {
    return this.userAuthentication;
  }

  /**
   * Assigns the user {@link Authentication} object from a previous authentication process.
   *
   * @param userAuthentication an {@link Authentication} object
   */
  public void setUserAuthentication(final Authentication userAuthentication) {
    this.userAuthentication = userAuthentication;
  }

  /**
   * Maps to {@link Saml2AuthnRequestAuthenticationToken#getCredentials()}.
   */
  @Override
  public Object getCredentials() {
    return this.authnRequestToken.getCredentials();
  }

  /**
   * Maps to {@link Saml2AuthnRequestAuthenticationToken#getPrincipal()}.
   */
  @Override
  public Object getPrincipal() {
    return this.authnRequestToken.getPrincipal();
  }

  /**
   * Gets the UI info - may be useful for IdP UI.
   *
   * @return a {@link Saml2ServiceProviderUiInfo}
   */
  public Saml2ServiceProviderUiInfo getUiInfo() {
    if (this.uiInfo == null) {
      this.uiInfo = Optional.ofNullable(this.authnRequestToken)
          .map(Saml2AuthnRequestAuthenticationToken::getPeerMetadata)
          .map(Saml2ServiceProviderUiInfo::new)
          .orElse(null);
    }
    return this.uiInfo;
  }

  /**
   * Maps to {@link Saml2AuthnRequestAuthenticationToken#getLogString()}.
   *
   * @return a formatted log string
   */
  public String getLogString() {
    return this.authnRequestToken.getLogString();
  }

}
