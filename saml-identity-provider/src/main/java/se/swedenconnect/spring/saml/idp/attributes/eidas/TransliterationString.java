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

import java.io.Serial;
import java.util.Objects;
import java.util.Optional;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.schema.XSBooleanValue;

import se.swedenconnect.opensaml.eidas.ext.attributes.TransliterationStringType;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Base class for {@link TransliterationStringType} values.
 *
 * @author Martin Lindström
 */
public class TransliterationString<T extends TransliterationStringType> implements EidasAttributeValue<T> {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** Whether the string is in latin script. */
  private final Boolean latinScript;

  /** The string value. */
  private final String stringValue;

  /** The XML type. */
  private final QName type;

  /** The class. */
  private final Class<T> clazz;

  /**
   * Constructor.
   *
   * @param value the attribute value
   * @param type the XML type
   * @param clazz the class
   */
  public TransliterationString(final T value, final QName type, final Class<T> clazz) {
    this.stringValue = Objects.requireNonNull(value, "value must not be null").getValue();
    this.latinScript = Optional.ofNullable(value.getLatinScriptXSBooleanValue())
        .map(XSBooleanValue::getValue)
        .orElse(null);
    this.type = Objects.requireNonNull(type, "type must not be null");
    this.clazz = Objects.requireNonNull(clazz, "clazz must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String getValueAsString() {
    return this.stringValue;
  }

  /** {@inheritDoc} */
  @Override
  public T createXmlObject() {
    final T xmlValue = AttributeBuilder.createValueObject(this.type, this.clazz);
    xmlValue.setValue(this.stringValue);
    xmlValue.setLatinScript(this.latinScript);
    return xmlValue;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.getValueAsString();
  }

}
