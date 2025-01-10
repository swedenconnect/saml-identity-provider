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
package se.swedenconnect.spring.saml.idp.error;

import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.context.MessageSource;

/**
 * An enum representing the different SAML error response messages that are handled in the system.
 *
 * @author Martin Lindström
 */
public enum Saml2ErrorStatus {

  /**
   * User authentication failed.
   */
  AUTHN_FAILED(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED, "idp.error.status.authn-failed",
      "User authentication failed"),

  /**
   * User cancelled authentication.
   */
  CANCEL(StatusCode.RESPONDER, "http://id.elegnamnden.se/status/1.0/cancel", "idp.error.status.cancel",
      "User cancelled authentication"),

  /**
   * SignMessage error. If the {@code SignMessage} is incorrectly constructed.
   */
  SIGN_MESSAGE(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED, "idp.error.status.sign-message-error",
      "Invalid SignMessage extension"),

  /**
   * The SignMessage could not be displayed.
   */
  SIGN_MESSAGE_NOT_DISPLAYED(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED,
      "idp.error.status.sign-message-not-displayed",
      "SignMessage could not be displayed"),

  /**
   * SignMessage error. If the {@code SignMessage} is incorrectly constructed.
   */
  SIGN_MESSAGE_DECRYPT(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED, "idp.error.status.sign-message-decrypt",
      "SignMessage decryption error"),

  /**
   * Invalid AuthnRequest.
   */
  INVALID_AUTHNREQUEST(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED, "idp.error.status.invalid-request",
      "Invalid authentication request"),

  /**
   * Invalid NameID policy given in AuthnRequest.
   */
  INVALID_NAMEID(StatusCode.REQUESTER, StatusCode.INVALID_NAMEID_POLICY, "idp.error.status.invalid-nameid",
      "Invalid NameIDPolicy in authentication request"),

  /**
   * PassiveAuthn could not be applied.
   */
  PASSIVE_AUTHN(StatusCode.REQUESTER, StatusCode.NO_PASSIVE, "idp.error.status.no-passive",
      "Passive authentication could not be performed"),

  /**
   * Requested authentication context is not supported.
   */
  NO_AUTHN_CONTEXT(StatusCode.REQUESTER, StatusCode.NO_AUTHN_CONTEXT, "idp.error.status.no-authn-context",
      "Requested authentication contexts not supported"),

  /**
   * Unknown principal.
   */
  UNKNOWN_PRINCIPAL(StatusCode.REQUESTER, StatusCode.UNKNOWN_PRINCIPAL, "idp.error.status.unknown-principal",
      "Unknown principal"),

  /**
   * Missing key descriptor for encryption of assertions.
   */
  ENCRYPT_NOT_POSSIBLE(StatusCode.REQUESTER, StatusCode.REQUEST_DENIED, "idp.error.status.no-encrypt-capabilities",
      "Missing key descriptor for encryption"),

  /**
   * Invalid UserMessage extension.
   */
  INVALID_USER_MESSAGE(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED, "idp.error.status.invalid-user-message",
      "Invalid UserMessage extension"),

  /**
   * SP is not allowed by to IdP policy.
   */
  NOT_AUTHORIZED(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED, "idp.error.status.not-authorized",
      "Not authorized to send requests");

  /**
   * Gets the main status code.
   *
   * @return the main status code
   */
  public String getStatusCode() {
    return this.statusCode;
  }

  /**
   * Gets the subordinate status code
   *
   * @return the subordinate status code
   */
  public String getSubStatusCode() {
    return this.subStatusCode;
  }

  /**
   * Gets the message code to use when resolving the status message against a {@link MessageSource}
   *
   * @return the message code
   */
  public String getStatusMessageCode() {
    return this.statusMessageCode;
  }

  /**
   * Gets the status message to use if no text can be resolved using the {@code statusMessageCode} ß
   *
   * @return the default status message
   */
  public String getDefaultStatusMessage() {
    return this.defaultStatusMessage;
  }

  /**
   * Constructor.
   *
   * @param statusCode the main status code
   * @param subStatusCode the subordinate status code
   * @param statusMessageCode the message code to use when resolving the status message against a
   *     {@link MessageSource}
   * @param defaultStatusMessage the status message to use if no text can be resolved using the
   *     {@code statusMessageCode}
   */
  Saml2ErrorStatus(
      final String statusCode, final String subStatusCode,
      final String statusMessageCode, final String defaultStatusMessage) {
    this.statusCode = statusCode;
    this.subStatusCode = subStatusCode;
    this.statusMessageCode = statusMessageCode;
    this.defaultStatusMessage = defaultStatusMessage;
  }

  /** The main status code. */
  private final String statusCode;

  /** The subordinate status code. */
  private final String subStatusCode;

  /** The message code for the status message. */
  private final String statusMessageCode;

  /** The default status message to use (if message sources don't contain the status message code). */
  private final String defaultStatusMessage;

}
