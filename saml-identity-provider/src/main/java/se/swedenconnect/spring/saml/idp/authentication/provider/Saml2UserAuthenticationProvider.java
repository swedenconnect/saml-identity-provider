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
package se.swedenconnect.spring.saml.idp.authentication.provider;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;

import se.swedenconnect.spring.saml.idp.attributes.release.AttributeProducer;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;

/**
 * Interface for an {@link AuthenticationProvider} that implements SAML2 Identity Provider user authentication. The
 * {@link #authenticate(org.springframework.security.core.Authentication)} method returns a
 * {@link Saml2UserAuthentication}.
 * 
 * <p>
 * Note: The authentication provider should release all possible attributes about an authentication (user). These will
 * be filtered by an {@link AttributeProducer} before adding attributes to an assertion. The reason for this is that in
 * SSO-cases another set of attributes may be requested, and if attributes are filtered by the provider we may not be
 * able to re-use and authentication.
 * </p>
 * <p>
 * Note that the {@link #authenticate(org.springframework.security.core.Authentication)} must only return {@code null}
 * under one condition and that is when the requested authentication context(s) can not be met by the authentication
 * provider.
 * </p>
 * 
 * @author Martin Lindström
 */
public interface Saml2UserAuthenticationProvider extends AuthenticationProvider {

  /**
   * Supports {@link Saml2UserAuthenticationInputToken}.
   */
  @Override
  default boolean supports(final Class<?> authentication) {
    return Saml2UserAuthenticationInputToken.class.isAssignableFrom(authentication);
  }

  /**
   * Gets the supported authentication context URI:s for the provider.
   * 
   * @return a list of the authenticator's supported authentication context URI:s
   */
  List<String> getSupportedAuthnContextUris();

  /**
   * Gets a list of all SAML entity categories that this {@link AuthenticationProvider} declares.
   * 
   * @return a list of entity category URI:s
   */
  List<String> getEntityCategories();

}
