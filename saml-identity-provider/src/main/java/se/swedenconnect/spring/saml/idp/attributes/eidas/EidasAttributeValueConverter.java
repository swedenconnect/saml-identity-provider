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

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Attribute;
import se.swedenconnect.opensaml.eidas.ext.attributes.CountryStringType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentAddressType;
import se.swedenconnect.opensaml.eidas.ext.attributes.DateOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.EidasAttributeValueType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderType;
import se.swedenconnect.opensaml.eidas.ext.attributes.PersonIdentifierType;
import se.swedenconnect.opensaml.eidas.ext.attributes.PlaceOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.TransliterationStringType;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;

import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Helper class for convering eIDAS attribute values to and from {@link UserAttribute}s.
 *
 * @author Martin Lindström
 */
@Slf4j
public class EidasAttributeValueConverter {

  // Hidden constructor
  private EidasAttributeValueConverter() {
  }

  /**
   * Predicate that tells if the supplied type is an eIDAS attribute type
   *
   * @param valueType the value type
   * @return {@code true} if the supplied type is an eIDAS attribute type and {@code false} otherwise
   */
  public static boolean isEidasAttribute(final Class<?> valueType) {
    return EidasAttributeValueType.class.isAssignableFrom(valueType);
  }

  /**
   * Extracts the attribute values from an eIDAS attribute.
   *
   * @param attribute the attribute
   * @param valueType the value type for the attribute value(s)
   * @return a list of values
   */
  public static List<? extends Serializable> getValues(final Attribute attribute, final Class<?> valueType) {
    if (PersonIdentifierType.class.isAssignableFrom(valueType)) {
      return attribute.getAttributeValues().stream()
          .map(PersonIdentifierType.class::cast)
          .map(PersonIdentifier::new)
          .collect(Collectors.toList());
    }
    if (TransliterationStringType.class.isAssignableFrom(valueType)) {
      return attribute.getAttributeValues().stream()
          .map(TransliterationStringType.class::cast)
          .map(TransliterationString::new)
          .collect(Collectors.toList());
    }
    if (DateOfBirthType.class.isAssignableFrom(valueType)) {
      return attribute.getAttributeValues().stream()
          .map(DateOfBirthType.class::cast)
          .map(DateOfBirth::new)
          .collect(Collectors.toList());
    }
    if (GenderType.class.isAssignableFrom(valueType)) {
      return attribute.getAttributeValues().stream()
          .map(GenderType.class::cast)
          .map(Gender::new)
          .collect(Collectors.toList());
    }
    if (PlaceOfBirthType.class.isAssignableFrom(valueType)) {
      return attribute.getAttributeValues().stream()
          .map(PlaceOfBirthType.class::cast)
          .map(PlaceOfBirth::new)
          .collect(Collectors.toList());
    }
    if (CurrentAddressType.class.isAssignableFrom(valueType)) {
      return attribute.getAttributeValues().stream()
          .map(CurrentAddressType.class::cast)
          .map(CurrentAddress::new)
          .collect(Collectors.toList());
    }
    if (CountryStringType.class.isAssignableFrom(valueType)) {
      return attribute.getAttributeValues().stream()
          .map(CountryStringType.class::cast)
          .map(CountryString::new)
          .collect(Collectors.toList());
    }

    log.warn("Unsupported eIDAS attribute - {}", attribute.getName());
    return attribute.getAttributeValues().stream()
        .map(UserAttribute.UnknownAttributeValue::new)
        .collect(Collectors.toList());
  }

}
