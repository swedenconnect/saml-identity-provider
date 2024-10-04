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
package se.swedenconnect.spring.saml.idp.error;

import org.springframework.context.MessageSource;

/**
 * An enum representing unrecoverable SAML errors, i.e., such errors that can not be signalled back to the SAML SP.
 *
 * @author Martin Lindström
 */
public enum UnrecoverableSaml2IdpError {

  /**
   * Internal error.
   */
  INTERNAL("idp.error.unrecoverable.internal", "An internal error occurred"),

  /**
   * The sender of an {@code AuthnRequest} message could not be found in SAML metadata.
   */
  UNKNOWN_PEER("idp.error.unrecoverable.unknown-peer",
      "The sender of the authentication request has not been registered at the Identity Provider"),

  /**
   * For replay (attacks) of authentication requests.
   */
  REPLAY_DETECTED("idp.error.unrecoverable.replay", "Authentication request message has already been processed"),

  /**
   * If timestamp checks fails.
   */
  MESSAGE_TOO_OLD("idp.error.unrecoverable.too-old", "Received message is too old and not accepted"),

  /**
   * The AssertionConsumerService indicated in the AuthnRequest is not registered in the Service Provider metadata.
   */
  INVALID_ASSERTION_CONSUMER_SERVICE("idp.error.unrecoverable.acs",
      "The indicated Assertion Consumer Service is not registered"),

  /**
   * Error reported if signed authentication requests are required, but a signature is missing from a received
   * authentication request.
   */
  MISSING_AUTHNREQUEST_SIGNATURE("idp.error.unrecoverable.no-signature",
      "Authentication request was not signed - this is required"),

  /**
   * Validation of signature on authentication request failed.
   */
  INVALID_AUTHNREQUEST_SIGNATURE("idp.error.unrecoverable.bad-signature",
      "Signature validation on received authentication request failed"),

  /**
   * Bad format on AuthnRequest.
   */
  INVALID_AUTHNREQUEST_FORMAT("idp.error.unrecoverable.format",
      "The format on the received authentication request is invalid"),

  /**
   * Failure to decode {@code AuthnRequest}.
   */
  FAILED_DECODE("idp.error.unrecoverable.decode",
      "The received message could not be decoded into a valid authentication request"),

  /**
   * Used if destination endpoint information does not match the actual endpoint on which the message was received.
   */
  ENDPOINT_CHECK_FAILURE("idp.error.unrecoverable.endpoint",
      "The endpoint information supplied in the authentication request do not correspond"
          + " with the endpoint on which the message was delivered"),

  /**
   * For session related errors.
   */
  INVALID_SESSION("idp.error.unrecoverable.session", "Required session data could not be found");

  /**
   * Gets the message code representing the error. This code may be used when mapping to a {@link MessageSource}.
   *
   * @return the message code
   */
  public String getMessageCode() {
    return this.messageCode;
  }

  /**
   * Gets the textual representation of the error. May be used in logs.
   *
   * @return the textual representation of the error
   */
  public String getDescription() {
    return this.description;
  }

  /**
   * Constructor.
   *
   * @param messageCode the error message code
   * @param description a textual description
   */
  UnrecoverableSaml2IdpError(final String messageCode, final String description) {
    this.messageCode = messageCode;
    this.description = description;
  }

  /** The error message code. */
  private final String messageCode;

  /** The textual description of the error. */
  private final String description;

}
