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
package se.swedenconnect.spring.saml.idp.attributes;

import java.util.Objects;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * An {@code ImplicitRequestedAttribute} is used to represent a requested attribute when the requirement is "implicit",
 * meaning that it is not explicitly stated in an {@code AuthnRequest} or {@link EntityDescriptor}.
 * <p>
 * The Swedish eID framework defines "service entity categories", that when declared by a Service Provider, states
 * requirements regarding requested attributes. This is an implicit requirement about which attributes a SP wishes to
 * receive. The problem here is that attributes are grouped together in "attribute sets", and a SP may declare more than
 * one service entity category, and an IdP may deliver attributes according to one or more service entity category.
 * Therefore, if a SP declared more than one service entity category and the IdP supports both, we can not state that
 * all attributes are "required", even though the are required within its service entity category. It's poor design from
 * the beginning, and we have to handle it in the best way we can.
 * <p>
 * See <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
 * Categories for the Swedish eID Framework</a>.
 * </p>
 * </p>
 * 
 * @author Martin Lindström
 */
public class ImplicitRequestedAttribute extends RequestedAttribute {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The origin to the implicit "requested attribute requirement". Normally an URI. */
  private final String origin;

  /**
   * Constructor.
   * 
   * @param origin the origin to the implicit "requested attribute requirement", normally an URI
   * @param id the attribute ID (name)
   * @param friendlyName the attribute friendly name
   * @param isRequired whether the attribute is "required", meaning that the requester requires it to be included in a
   *          resulting assertion
   */
  public ImplicitRequestedAttribute(
      final String origin, final String id, final String friendlyName, final boolean isRequired) {
    super(id, friendlyName, isRequired);
    this.origin = Objects.requireNonNull(origin, "origin must not be null");
  }

  /**
   * Gets the origin to the implicit "requested attribute requirement". Normally an URI.
   * 
   * @return the origin (URI)
   */
  public String getOrigin() {
    return this.origin;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("(%s) %s", this.origin, super.toString());
  }

}
