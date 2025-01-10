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

import se.swedenconnect.opensaml.sweid.saml2.authn.psc.PrincipalSelection;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

import java.util.Collection;

/**
 * Extracts the {@link PrincipalSelection} extension values. See <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/14_-_Principal_Selection_in_SAML_Authentication_Requests.html">PrincipalSelection</a>.
 *
 * @author Martin Lindström
 */
public interface PrincipalSelectionProcessor {

  /**
   * Extracts the {@link PrincipalSelection} extension values and returns these as a collection of {@link UserAttribute}
   * objects. See <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/14_-_Principal_Selection_in_SAML_Authentication_Requests.html">PrincipalSelection</a>.
   *
   * @param authnRequestToken the authentication request token
   * @return a (possibly empty) collection of {@link UserAttribute} objects
   */
  Collection<UserAttribute> extractPrincipalSelection(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken);

}
