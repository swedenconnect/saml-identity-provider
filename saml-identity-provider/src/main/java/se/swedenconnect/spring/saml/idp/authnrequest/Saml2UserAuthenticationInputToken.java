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
package se.swedenconnect.spring.saml.idp.authnrequest;

import java.util.Collections;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * An {@link Authentication} object that represents the input for SAML user authentication.
 * 
 * @author Martin Lindström
 */
public class Saml2UserAuthenticationInputToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The token holding the authentication request information. */
  private final Saml2AuthnRequestAuthenticationToken authnRequestToken;

  /** The (calculated) authentication requirements. */
  private final AuthenticationRequirements requirements;

  /**
   * Constructor.
   * 
   * @param authnRequestToken the authentication request token
   * @param requirements the authentication requirements
   */
  public Saml2UserAuthenticationInputToken(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken,
      final AuthenticationRequirements requirements) {
    super(Collections.emptyList());
    this.authnRequestToken = Objects.requireNonNull(authnRequestToken, "authnRequestToken must not be null");
    this.requirements = Objects.requireNonNull(requirements, "requirements must not be null");
    this.setAuthenticated(authnRequestToken.isAuthenticated());
  }

  /**
   * Gets the {@link Saml2AuthnRequestAuthenticationToken} holding information about the authentication request.
   * 
   * @return the {@link Saml2AuthnRequestAuthenticationToken}
   */
  public Saml2AuthnRequestAuthenticationToken getAuthnRequestToken() {
    return this.authnRequestToken;
  }

  /**
   * Gets the {@link AuthenticationRequirements} that is an object representing the requirements for the user
   * authentication.
   * 
   * @return an {@link AuthenticationRequirements}
   */
  public AuthenticationRequirements getRequirements() {
    return this.requirements;
  }

  /**
   * Returns an empty string.
   */
  @Override
  public Object getCredentials() {
    return "";
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Object getPrincipal() {
    return this.authnRequestToken.getPrincipal();
  }

}
