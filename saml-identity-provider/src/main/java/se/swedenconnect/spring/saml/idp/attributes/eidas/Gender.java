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
package se.swedenconnect.spring.saml.idp.attributes.eidas;

import java.io.Serial;
import java.util.Objects;

import se.swedenconnect.opensaml.eidas.ext.attributes.GenderType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderTypeEnumeration;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Representation of the eIDAS {@link GenderType} attribute value.
 *
 * @author Martin Lindström
 */
public class Gender implements EidasAttributeValue<GenderType> {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  private final String gender;

  /**
   * Constructor.
   *
   * @param gender the gender type
   */
  public Gender(final GenderType gender) {
    this.gender = Objects.requireNonNull(gender, "gender must not be null").getGender().getValue();
  }

  /** {@inheritDoc} */
  @Override
  public String getValueAsString() {
    return this.gender;
  }

  /** {@inheritDoc} */
  @Override
  public GenderType createXmlObject() {
    final GenderType xmlValue = AttributeBuilder.createValueObject(GenderType.TYPE_NAME, GenderType.class);
    xmlValue.setGender(GenderTypeEnumeration.fromValue(this.gender));
    return xmlValue;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.gender;
  }

}
