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
package se.swedenconnect.spring.saml.idp.events;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;

/**
 * An event that is signalled before the user is handed over to the {@link UserAuthenticationProvider} to be
 * authenticated.
 * 
 * @author Martin Lindström
 */
public class Saml2PreUserAuthenticationEvent extends AbstractSaml2IdpEvent {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   * 
   * @param authn the {@link Saml2UserAuthenticationInputToken}
   */
  public Saml2PreUserAuthenticationEvent(final Saml2UserAuthenticationInputToken authn) {
    super(authn);
  }

  /**
   * Gets the {@link Saml2UserAuthenticationInputToken}.
   * 
   * @return the {@link Saml2UserAuthenticationInputToken}
   */
  public Saml2UserAuthenticationInputToken getUserAuthenticationInput() {
    return Saml2UserAuthenticationInputToken.class.cast(this.getSource());
  }

}
