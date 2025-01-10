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
package se.swedenconnect.spring.saml.idp.events;

import org.opensaml.saml.saml2.core.AuthnRequest;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

import java.io.Serial;

/**
 * Event that signals that a SAML2 {@link AuthnRequest} has been received. Note that the request has not been verified
 * at this point.
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestReceivedEvent extends AbstractSaml2IdpEvent {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param token a {@link Saml2AuthnRequestAuthenticationToken}
   */
  public Saml2AuthnRequestReceivedEvent(final Saml2AuthnRequestAuthenticationToken token) {
    super(token);
  }

  /**
   * Gets the {@link Saml2AuthnRequestAuthenticationToken} for this event.
   *
   * @return a {@link Saml2AuthnRequestAuthenticationToken}
   * @see #getSource()
   */
  public Saml2AuthnRequestAuthenticationToken getAuthnRequestToken() {
    return (Saml2AuthnRequestAuthenticationToken) this.getSource();
  }

  /**
   * Gets the SAML entityID of the SP that sent the {@code AuthnRequest} message.
   *
   * @return the SP SAML entityID
   */
  public String getSpEntityId() {
    return this.getAuthnRequestToken().getEntityId();
  }

  /**
   * Gets the received {@link AuthnRequest} message.
   *
   * @return the {@link AuthnRequest}
   */
  public AuthnRequest getAuthnRequest() {
    return this.getAuthnRequestToken().getAuthnRequest();
  }

}
