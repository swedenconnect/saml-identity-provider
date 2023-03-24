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
package se.swedenconnect.spring.saml.idp.attributes.release;

import org.opensaml.saml.saml2.core.Attribute;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;

/**
 * A voter functioning according to the rules specified in
 * <a href="https://docs.swedenconnect.se/technical-framework/">Technical Specifications for the Swedish eID
 * Framework</a>.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class SwedenConnectAttributeReleaseVoter implements AttributeReleaseVoter {

  /**
   * Applies the following rules:
   * <ul>
   * <li>If the attribute is "urn:oid:1.2.752.29.4.13" (personalIdentityNumber) and the contents is a Swedish
   * coordination number (as opposed to the civic registration number) we require that the SP has opted in to received
   * coordination numbers.</li>
   * <li>TODO ...</li>
   * </ul>
   */
  @Override
  public AttributeReleaseVote vote(final Saml2UserAuthentication token, final Attribute attribute) {

    // Check opt-in regarding coordination numbers ...
    //
    if (AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER.equals(attribute.getName())) {
      final String id = AttributeUtils.getAttributeStringValue(attribute);
      if (id == null) {
        log.error("Attribute '{}' has no value [{}]", attribute.getName(), token.getAuthnRequestToken().getLogString());
        return AttributeReleaseVote.DONT_INCLUDE;
      }
      if (isCoordinationNumber(id)) {
        if (token.getAuthnRequirements().getEntityCategories().contains(
            EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER.getUri())) {
          return AttributeReleaseVote.INCLUDE;
        }
        else {
          log.info("Attribute '{}' will not be released since it is a coordination number and the SP has"
              + " not opted-in ({} not declared) [{}]", attribute.getName(),
              EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER.getUri(),
              token.getAuthnRequestToken().getLogString());

          return AttributeReleaseVote.DONT_INCLUDE;
        }
      }
    }

    return AttributeReleaseVote.DONT_KNOW;
  }

  /**
   * Predicate that tells if the supplied personal identity number is a Swedish coordination number (samordningsnummer).
   * 
   * @param id the personal identity number
   * @return true if the number is a coordination number and false otherwise
   */
  private static boolean isCoordinationNumber(final String id) {
    if (id.length() != 12) {
      return false;
    }
    try {
      final Integer day = Integer.parseInt(id.substring(6, 8));
      return (day >= 61);
    }
    catch (final Exception e) {
      return false;
    }
  }

}
