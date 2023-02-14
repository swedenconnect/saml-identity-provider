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
package se.swedenconnect.spring.saml.idp.authentication;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;

import se.swedenconnect.spring.saml.idp.authnrequest.Saml2UserAuthenticationInputToken;

/**
 * Interface for an {@link AuthenticationProvider} that implements SAML2 Identity Provider user authentication. The
 * {@link #authenticate(org.springframework.security.core.Authentication)} method returns a
 * {@link Saml2UserAuthentication}.
 * 
 * @author Martin Lindström
 */
public interface Saml2UserAuthenticationProvider extends AuthenticationProvider {

  /**
   * Gets a list of URI:s representing the authentication context URI:s that supported by this IdP.
   * 
   * @return a list of authentication context URI:s
   */
  List<String> getAssuranceCertificationUris();

  /**
   * Gets a list of entity category URI:s that this IdP declares.
   * 
   * @return a list of entity category URI:s
   */
  List<String> getEntityCategories();

  /**
   * Supports {@link Saml2UserAuthenticationInputToken}.
   */
  @Override
  default boolean supports(final Class<?> authentication) {
    return Saml2UserAuthenticationInputToken.class.isAssignableFrom(authentication);
  }

}
