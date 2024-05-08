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
package se.swedenconnect.spring.saml.idp.audit;

/**
 * Constants for all audit event types produced by the SAML IdP.
 *
 * @author Martin Lindström
 */
public enum Saml2AuditEvents {

  /** An {@code AuthnRequest} message has been received. */
  SAML2_AUDIT_REQUEST_RECEIVED("SAML2_REQUEST_RECEIVED"),

  /** A successful SAML response is about to be sent. */
  SAML2_AUDIT_SUCCESSFUL_RESPONSE("SAML2_SUCCESS_RESPONSE"),

  /** An error SAML response is about to be sent. */
  SAML2_AUDIT_ERROR_RESPONSE("SAML2_ERROR_RESPONSE"),

  /** A request has been received and successfully processed, but the user has not yet been authenticated. */
  SAML2_AUDIT_BEFORE_USER_AUTHN("SAML2_BEFORE_USER_AUTHN"),

  /** The user has been successfully authenticated, but the SAML assertion has not yet been created. */
  SAML2_AUDIT_AFTER_USER_AUTHN("SAML2_AFTER_USER_AUTHN"),

  /** An error occurred, and we could not direct the user back to the SP. */
  SAML2_AUDIT_UNRECOVERABLE_ERROR("SAML2_UNRECOVERABLE_ERROR");


  /** The event type name. */
  private final String typeName;

  /**
   * Constructor.
   *
   * @param typeName the event type name
   */
  Saml2AuditEvents(final String typeName) {
    this.typeName = typeName;
  }

  /**
   * Gets the event type name.
   * @return the event type name
   */
  public String getTypeName() {
    return this.typeName;
  }
}
