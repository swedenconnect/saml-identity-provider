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
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

import java.io.Serial;

/**
 * An event that is signalled if an {@link UnrecoverableSaml2IdpException} is thrown. These types of errors means that
 * the user can not be redirected back to the SP (i.e., no SAML response can be sent). Instead, an error view is
 * displayed.
 *
 * @author Martin Lindström
 */
public class Saml2UnrecoverableErrorEvent extends AbstractSaml2IdpEvent {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param error the {@link UnrecoverableSaml2IdpException}
   */
  public Saml2UnrecoverableErrorEvent(final UnrecoverableSaml2IdpException error) {
    super(error);
  }

  /**
   * Gets the error.
   *
   * @return the {@link UnrecoverableSaml2IdpException}
   */
  public UnrecoverableSaml2IdpException getError() {
    return (UnrecoverableSaml2IdpException) this.getSource();
  }

}
