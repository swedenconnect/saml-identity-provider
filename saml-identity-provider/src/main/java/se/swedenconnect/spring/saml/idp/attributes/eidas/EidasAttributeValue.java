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

import java.io.Serializable;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;

/**
 * Interface representing an eIDAS attribute value.
 *
 * @param <T> the eIDAS type
 *
 * @author Martin Lindström
 */
public interface EidasAttributeValue<T extends XMLObject> extends Serializable {

  /**
   * Gets the string representation of the value.
   *
   * @return a string
   */
  String getValueAsString();

  /**
   * Creates the {@link XMLObject} value for insertion as an attribute value in an {@link Assertion}.
   *
   * @return the attribute value
   */
  T createXmlObject();

}
