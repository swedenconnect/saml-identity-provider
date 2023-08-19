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

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * An event that signals that a successful SAML response is being sent.
 * 
 * @author Martin Lindström
 */
public class Saml2SuccessResponseEvent extends AbstractSaml2IdpEvent {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The issued SAML assertion (un-encrypted). */
  private final Assertion assertion;

  /** The entityID of the SP that we are sending the response to. */
  private String spEntityId;

  /**
   * Constructor.
   * 
   * @param response the SAML response
   * @param assertion the SAML Assertion (before being encrypted)
   * @param spEntityId the entityID of the SP that we are sending the response to
   */
  public Saml2SuccessResponseEvent(final Response response, final Assertion assertion, final String spEntityId) {
    super(response);
    this.assertion = assertion;
    this.spEntityId = spEntityId;
  }

  /**
   * Gets the SAML response.
   * 
   * @return the {@link Response}
   */
  public Response getResponse() {
    return Response.class.cast(this.getSource());
  }

  /**
   * Gets the (un-encrypted) SAML {@link Assertion}
   * 
   * @return an {@link Assertion}
   */
  public Assertion getAssertion() {
    return this.assertion;
  }

  /**
   * Gets the entityID of the SP that we are sending the response to.
   * 
   * @return SP SAML entityID
   */
  public String getSpEntityId() {
    return this.spEntityId;
  }

}
