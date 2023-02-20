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

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * Representation of a user authenticated using SAML2.
 *
 * @author Martin Lindström
 */
public class Saml2UserDetails implements UserDetails {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The user identity attributes. */
  private final Collection<UserAttribute> attributes;

  /** The ID of the primary attribute (that must appear among the attributes). */
  private final String primaryAttribute;

  /** The authentication context URI under which the authentication was made. */
  private final String authnContextUri;

  /** The authentication instant. */
  private final Instant authnInstant;

  /** The subject locality, an IP-address. */
  private final String subjectIpAddress;

  /**
   * If the authentication was performed by another provider and the current IdP acts as a proxy, this field holds the
   * ID of the authenticating authority.
   */
  private String authenticatingAuthority;

  /**
   * Constructor.
   *
   * @param attributes the user identity attributes
   * @param primaryAttribute the ID of the primary attribute (that must appear among the attributes)
   * @param authnContextUri the authentication context URI under which the authentication was made
   * @param authnInstant the authentication instant
   */
  public Saml2UserDetails(
      final Collection<UserAttribute> attributes, final String primaryAttribute, final String authnContextUri,
      final Instant authnInstant, final String subjectIpAddress) {

    this.attributes = Optional.ofNullable(attributes).filter(a -> !a.isEmpty())
        .orElseThrow(() -> new IllegalArgumentException("attributes must be set and not empty"));
    this.primaryAttribute = Optional.ofNullable(primaryAttribute)
        .filter(p -> this.attributes.stream().anyMatch(a -> Objects.equals(a.getId(), p) && !a.getValues().isEmpty()))
        .orElseThrow(
            () -> new IllegalArgumentException("primaryAttribute must be set and appear among the attributes"));
    this.authnContextUri = Optional.ofNullable(authnContextUri).filter(StringUtils::hasText)
        .orElseThrow(() -> new IllegalArgumentException("authnContextUri must be set and not empty"));
    this.authnInstant = Objects.requireNonNull(authnInstant, "authnInstant must not be null");
    this.subjectIpAddress = Objects.requireNonNull(subjectIpAddress, "subjectIpAddress must not be null");
  }

  /**
   * Returns the attribute value for the {@code primaryAttribute}.
   */
  @Override
  public String getUsername() {
    return this.attributes.stream()
        .filter(a -> this.primaryAttribute.equals(a.getId()))
        .map(a -> a.getValues().get(0))
        .map(Object::toString)
        .findFirst()
        .orElseThrow(() -> new RuntimeException("Missing user name"));
  }

  /**
   * Gets an unmodifiable collection of all user attributes.
   * 
   * @return the user attributes
   */
  public Collection<UserAttribute> getAttributes() {
    return Collections.unmodifiableCollection(this.attributes);
  }

  /**
   * Gets the ID of the primary attribute (that must appear among the attributes).
   * 
   * @return the primary attribute ID
   */
  public String getPrimaryAttribute() {
    return this.primaryAttribute;
  }

  /**
   * Gets the authentication context URI under which the authentication was made.
   * 
   * @return the authn context URI
   */
  public String getAuthnContextUri() {
    return this.authnContextUri;
  }

  /**
   * Gets the authentication instant.
   * 
   * @return the authentication instant
   */
  public Instant getAuthnInstant() {
    return this.authnInstant;
  }

  /**
   * Gets the subject locality, an IP-address.
   * 
   * @return the subject locality
   */
  public String getSubjectIpAddress() {
    return this.subjectIpAddress;
  }

  /**
   * If the authentication was performed by another provider and the current IdP acts as a proxy, this field holds the
   * ID of the authenticating authority.
   * 
   * @return the authenticating authority, or {@code null} if not set
   */
  public String getAuthenticatingAuthority() {
    return this.authenticatingAuthority;
  }

  /**
   * Assigns the authenticating authority. If the authentication was performed by another provider and the current IdP
   * acts as a proxy, this field holds the ID of the authenticating authority.
   * 
   * @param authenticatingAuthority the authenticating authority
   */
  public void setAuthenticatingAuthority(final String authenticatingAuthority) {
    this.authenticatingAuthority = authenticatingAuthority;
  }

  /**
   * Will always return en empty collection.
   */
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Collections.emptyList();
  }

  /**
   * Always returns the empty string.
   */
  @Override
  public String getPassword() {
    return "";
  }

  /**
   * Always returns {@code true}.
   */
  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  /**
   * Always returns {@code true}.
   */
  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  /**
   * Always returns {@code true}.
   */
  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  /**
   * Always returns {@code true}.
   */
  @Override
  public boolean isEnabled() {
    return true;
  }

}
