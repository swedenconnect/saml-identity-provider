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

import org.opensaml.core.xml.schema.XSBooleanValue;
import se.swedenconnect.opensaml.eidas.ext.attributes.TransliterationStringType;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import javax.xml.namespace.QName;
import java.io.Serial;
import java.util.Objects;
import java.util.Optional;

/**
 * Base class for {@link TransliterationStringType} values.
 *
 * @author Martin Lindström
 */
public class TransliterationString implements EidasAttributeValue<TransliterationStringType> {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** Whether the string is in latin script. */
  private final Boolean latinScript;

  /** The string value. */
  private final String stringValue;

  /** The XML type. */
  private final QName type;

  /**
   * Constructor.
   *
   * @param value the attribute value
   */
  public TransliterationString(final TransliterationStringType value) {
    this.stringValue = Objects.requireNonNull(value, "value must not be null").getValue();
    this.latinScript = Optional.ofNullable(value.getLatinScriptXSBooleanValue())
        .map(XSBooleanValue::getValue)
        .orElse(null);
    this.type = value.getSchemaType();
  }

  /** {@inheritDoc} */
  @Override
  public String getValueAsString() {
    return this.stringValue;
  }

  /** {@inheritDoc} */
  @Override
  public TransliterationStringType createXmlObject() {
    final TransliterationStringType xmlValue =
        AttributeBuilder.createValueObject(this.type, TransliterationStringType.class);
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
