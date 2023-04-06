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
package se.swedenconnect.spring.saml.idp.authentication;

import java.util.Collections;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.authnrequest.AuthenticationRequirements;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * An {@link Authentication} token that represents the authentication of a user. This will later be translated into a
 * SAML Assertion.
 * 
 * @author Martin Lindström
 */
public class Saml2UserAuthentication extends AbstractAuthenticationToken {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The user details. */
  private final Saml2UserDetails userDetails;

  /**
   * Flag telling whether this {@link Authentication} object may be "re-used", i.e., whether it may be used in
   * SSO-scenarios. Defaults to {@code true}.
   * <p>
   * Note that even if this flag is {@code true} the IdP-engine may choose not to save the {@link Authentication} object
   * for future use. This may be dependent on other parameters. However, if the flag is {@code false} the authentication
   * will not be saved.
   * </p>
   */
  private boolean reuseAuthentication = true;

  /** Information about the AuthnRequest that led to the user being authenticated. */
  private Saml2AuthnRequestAuthenticationToken authnRequestToken;

  /** The authentication requirements deduced from the authentication request and IdP policy. */
  private AuthenticationRequirements authnRequirements;

  /**
   * Constructor.
   * 
   * @param userDetails the user details
   */
  public Saml2UserAuthentication(final Saml2UserDetails userDetails) {
    super(Collections.emptyList());
    this.setDetails(userDetails);
    this.userDetails = Objects.requireNonNull(userDetails, "userDetails must not be null");
    this.setAuthenticated(true);
  }

  /**
   * Maps to {@link #getSaml2UserDetails()}.
   */
  @Override
  public Object getPrincipal() {
    return this.userDetails;
  }

  /**
   * Gets the {@link Saml2UserDetails}.
   * 
   * @return the {@link Saml2UserDetails}
   */
  public Saml2UserDetails getSaml2UserDetails() {
    return this.userDetails;
  }

  /**
   * Gets the flag telling whether this {@link Authentication} object may be "re-used", i.e., whether it may be used in
   * SSO-scenarios. Defaults to {@code true}.
   * <p>
   * Note that even if this flag is {@code true} the IdP-engine may choose not to save the {@link Authentication} object
   * for future use. This may be dependent on other parameters. However, if the flag is {@code false} the authentication
   * will not be saved.
   * </p>
   * 
   * @return whether the authentication object should be saved for future SSO
   */
  public boolean isReuseAuthentication() {
    return this.reuseAuthentication;
  }

  /**
   * Assigns the flag telling whether this {@link Authentication} object may be "re-used", i.e., whether it may be used
   * in SSO-scenarios.
   * 
   * @param reuseAuthentication whether the authentication object should be saved for future SSO
   */
  public void setReuseAuthentication(final boolean reuseAuthentication) {
    this.reuseAuthentication = reuseAuthentication;
  }

  /**
   * Will always return the empty string.
   */
  @Override
  public Object getCredentials() {
    return "";
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
   * Assigns the authentication request token.
   * 
   * @param authnRequestToken the authentication request token
   */
  public void setAuthnRequestToken(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken) {
    this.authnRequestToken = authnRequestToken;
  }

  /**
   * Clears the authentication request token. This is done when the SAML response has been sent. The
   * {@link Saml2UserAuthentication} object will be persisted, and there is no need to carry around the authentication
   * request information.
   */
  public void clearAuthnRequestToken() {
    this.authnRequestToken = null;
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
   * Assigns the authentication requirements.
   * 
   * @param authnRequirements the authentication requirements
   */
  public void setAuthnRequirements(final AuthenticationRequirements authnRequirements) {
    this.authnRequirements = authnRequirements;
  }

  /**
   * Clears the authentication requirements. This is done when the SAML response has been sent. The
   * {@link Saml2UserAuthentication} object will be persisted, and there is no need to carry around non-needed
   * information.
   */
  public void clearAuthnRequirements() {
    this.authnRequirements = null;
  }

}
