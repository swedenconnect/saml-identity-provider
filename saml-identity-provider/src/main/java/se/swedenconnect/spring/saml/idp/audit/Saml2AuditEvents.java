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
package se.swedenconnect.spring.saml.idp.audit;

/**
 * Symbolic constants for all audit event types produced by the SAML IdP.
 * 
 * @author Martin Lindström
 */
public class Saml2AuditEvents {

  /** An {@code AuthnRequest} message has been received. */
  public static final String SAML2_AUDIT_REQUEST_RECEIVED = "SAML2_REQUEST_RECEIVED";

  /** A successful SAML response is about to be sent. */
  public static final String SAML2_AUDIT_SUCCESSFUL_RESPONSE = "SAML2_SUCCESS_RESPONSE";

  /** An error SAML response is about to be sent. */
  public static final String SAML2_AUDIT_ERROR_RESPONSE = "SAML2_ERROR_RESPONSE";

  /** A request has been received and successfully processed, but the user has not yet been authenticated. */
  public static final String SAML2_AUDIT_BEFORE_USER_AUTHN = "SAML2_BEFORE_USER_AUTHN";
  
  /** The user has been successfully authenticated, but the SAML assertion has not yet been created. */
  public static final String SAML2_AUDIT_AFTER_USER_AUTHN = "SAML2_AFTER_USER_AUTHN";
  
  /** An error occurred and we could not direct the user back to the SP. */
  public static final String SAML2_AUDIT_UNRECOVERABLE_ERROR = "SAML2_UNRECOVERABLE_ERROR";

  // Hidden constructor
  private Saml2AuditEvents() {
  }

}
