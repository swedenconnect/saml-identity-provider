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
package se.swedenconnect.spring.saml.idp.events;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;

import java.io.Serial;

/**
 * An event that is fired after the user has been authenticated by a {@link UserAuthenticationProvider} but before we
 * filter release attributes and compile the SAML assertion.
 *
 * @author Martin Lindström
 */
public class Saml2PostUserAuthenticationEvent extends AbstractSaml2IdpEvent {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param auth the {@link Saml2UserAuthentication}
   */
  public Saml2PostUserAuthenticationEvent(final Saml2UserAuthentication auth) {
    super(auth);
  }

  /**
   * Gets the {@link Saml2UserAuthentication} representing the user authentication.
   *
   * @return a {@link Saml2UserAuthentication}
   */
  public Saml2UserAuthentication getUserAuthentication() {
    return (Saml2UserAuthentication) this.getSource();
  }

}
