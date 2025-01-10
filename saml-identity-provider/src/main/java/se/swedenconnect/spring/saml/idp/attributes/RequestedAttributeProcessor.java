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
package se.swedenconnect.spring.saml.idp.attributes;

import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

import java.util.Collection;

/**
 * A processor for locating information about which user attributes that are requested.
 *
 * @author Martin Lindström
 */
public interface RequestedAttributeProcessor {

  /**
   * Given the {@link Saml2AuthnRequestAuthenticationToken} the method will locate {@link RequestedAttribute}s.
   *
   * @param authnRequestToken the authentication request token
   * @return a (possibly empty) collection of {@link RequestedAttribute}s
   */
  Collection<RequestedAttribute> extractRequestedAttributes(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken);

}
