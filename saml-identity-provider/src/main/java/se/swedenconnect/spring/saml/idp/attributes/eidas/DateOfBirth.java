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

import se.swedenconnect.opensaml.eidas.ext.attributes.DateOfBirthType;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import java.io.Serial;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.Optional;

/**
 * Date of birth.
 *
 * @author Martin Lindström
 */
public class DateOfBirth implements EidasAttributeValue<DateOfBirthType> {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The date time formatter to use. */
  private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE;

  /** The value. */
  private final LocalDate value;

  /**
   * Constructor.
   *
   * @param value the XML value object
   */
  public DateOfBirth(final DateOfBirthType value) {
    this.value = Objects.requireNonNull(value, "value must not be null").getDate();
  }

  /** {@inheritDoc} */
  @Override
  public String getValueAsString() {
    return Optional.ofNullable(this.value)
        .map(formatter::format)
        .orElse("");
  }

  /** {@inheritDoc} */
  @Override
  public DateOfBirthType createXmlObject() {
    final DateOfBirthType xmlValue =
        AttributeBuilder.createValueObject(DateOfBirthType.TYPE_NAME, DateOfBirthType.class);
    xmlValue.setDate(this.value);
    return xmlValue;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.getValueAsString();
  }

}
