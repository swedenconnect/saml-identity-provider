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
package se.swedenconnect.spring.saml.idp.attributes.eidas;

import se.swedenconnect.opensaml.eidas.ext.attributes.CountryStringType;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import javax.xml.namespace.QName;
import java.io.Serial;
import java.util.Objects;

/**
 * Supports the eIDAS attributes Nationality, CountryOfResidence and CountryOfBirth.
 *
 * @author Martin Lindström
 */
public class CountryString implements EidasAttributeValue<CountryStringType> {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The contents of the attribute value. */
  private final String value;

  /** The XML type. */
  private final QName type;

  /**
   * Constructor.
   *
   * @param value the attribute value
   */
  public CountryString(final CountryStringType value) {
    this.value = Objects.requireNonNull(value, "value must not be null").getValue();
    this.type = value.getSchemaType();
  }

  /** {@inheritDoc} */
  @Override
  public String getValueAsString() {
    return this.value;
  }

  /** {@inheritDoc} */
  @Override
  public CountryStringType createXmlObject() {
    final CountryStringType xmlValue = AttributeBuilder.createValueObject(this.type, CountryStringType.class);
    xmlValue.setValue(this.value);
    return xmlValue;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.value;
  }

}
