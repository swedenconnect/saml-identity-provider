/*
 * Copyright 2023-2024 Sweden Connect
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

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import java.io.Serial;
import java.io.Serializable;

/**
 * A representation of a "requested attribute".
 *
 * @author Martin Lindström
 */
public class RequestedAttribute extends UserAttribute {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Whether the attribute is "required", meaning that the requester requires it to be included in a resulting
   * assertion.
   */
  private boolean isRequired = false;

  /**
   * Constructor.
   *
   * @param id the attribute ID (name)
   */
  public RequestedAttribute(final String id) {
    super(id);
  }

  /**
   * Constructor.
   *
   * @param id the attribute ID (name)
   * @param friendlyName the attribute friendly name
   */
  public RequestedAttribute(final String id, final String friendlyName) {
    super(id, friendlyName, (Serializable) null);
  }

  /**
   * Constructor.
   *
   * @param id the attribute ID (name)
   * @param friendlyName the attribute friendly name
   * @param isRequired whether the attribute is "required", meaning that the requester requires it to be included in
   *     a resulting assertion
   */
  public RequestedAttribute(final String id, final String friendlyName, final boolean isRequired) {
    super(id, friendlyName, (Serializable) null);
    this.isRequired = isRequired;
  }

  /**
   * Constructor creating an {@link RequestedAttribute} from an OpenSAML eIDAS
   * {@link se.swedenconnect.opensaml.eidas.ext.RequestedAttribute}.
   *
   * @param attribute the eIDAS {@link se.swedenconnect.opensaml.eidas.ext.RequestedAttribute}
   */
  public RequestedAttribute(final se.swedenconnect.opensaml.eidas.ext.RequestedAttribute attribute) {
    super(attribute);
    this.isRequired = attribute.isRequired();
  }

  /**
   * Constructor creating an {@link RequestedAttribute} from an OpenSAML SAML metadata
   * {@link org.opensaml.saml.saml2.metadata.RequestedAttribute}.
   *
   * @param attribute the {@link org.opensaml.saml.saml2.metadata.RequestedAttribute}
   */
  public RequestedAttribute(final org.opensaml.saml.saml2.metadata.RequestedAttribute attribute) {
    super(attribute);
    this.isRequired = attribute.isRequired();
  }

  /**
   * Predicate telling whether the attribute is "required", meaning that the requester requires it to be included in a
   * resulting assertion.
   *
   * @return {@code true} if the attribute is required and {@code false} otherwise
   */
  public boolean isRequired() {
    return this.isRequired;
  }

  /**
   * Assigns whether the attribute is "required", meaning that the requester requires it to be included in a resulting
   * assertion.
   *
   * @param isRequired the is-required flag
   */
  public void setRequired(final boolean isRequired) {
    this.isRequired = isRequired;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "%s, is-required=%s".formatted(super.toString(), this.isRequired);
  }

}
