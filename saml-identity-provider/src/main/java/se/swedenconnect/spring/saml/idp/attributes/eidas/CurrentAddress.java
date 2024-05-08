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

import java.io.ByteArrayInputStream;
import java.io.Serial;
import java.util.Objects;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.w3c.dom.Element;

import net.shibboleth.shared.xml.SerializeSupport;
import net.shibboleth.shared.xml.XMLParserException;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentAddressType;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * {@link CurrentAddressType}.
 *
 * @author Martin Lindström
 */
public class CurrentAddress implements EidasAttributeValue<CurrentAddressType> {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The value. */
  private final String value;

  /** String representation. */
  private final String stringRepr;

  /**
   * Constructor.
   *
   * @param value the attribute value object
   */
  public CurrentAddress(final CurrentAddressType value) {
    try {
      final Element element = XMLObjectSupport.marshall(Objects.requireNonNull(value, "value must not be null"));
      this.value = SerializeSupport.nodeToString(element);
      this.stringRepr = value.toSwedishEidString();
    }
    catch (final MarshallingException e) {
      throw new IllegalArgumentException("Failed to marshall CurrentAddressType", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getValueAsString() {
    return this.stringRepr;
  }

  /** {@inheritDoc} */
  @Override
  public CurrentAddressType createXmlObject() {
    try {
      return (CurrentAddressType) XMLObjectSupport.unmarshallFromInputStream(
          Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool()),
          new ByteArrayInputStream(this.value.getBytes()));
    }
    catch (final XMLParserException | UnmarshallingException e) {
      throw new SecurityException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.getValueAsString();
  }

}
