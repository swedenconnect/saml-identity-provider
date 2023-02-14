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
package se.swedenconnect.spring.saml.idp.error;

import java.util.Locale;
import java.util.Objects;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * Exception class that when thrown will lead to a SAML error status message being sent.
 * <p>
 * A message source code, and optionally parameters, may be supplied. This message code is resolved into a text that is
 * used as the {@code Status} status message.
 * </p>
 * 
 * @author Martin Lindström
 */
public class Saml2ErrorStatusException extends AuthenticationException {

  /** For serializing. */
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The major status code. */
  private final String statusCode;

  /** The minor status code. */
  private final String subStatusCode;

  /** Message code. May be null. */
  private String statusMessageCode;

  /** The status message to use if the {@code statusMessageCode} can not be resolved against a {@link MessageSource}. */
  private String defaultStatusMessage;

  /**
   * Constructor.
   * 
   * @param status the {@link Saml2ErrorStatus}
   */
  public Saml2ErrorStatusException(final Saml2ErrorStatus status) {
    this(status, status.getDefaultStatusMessage(), null);
  }

  /**
   * Constructor.
   * 
   * @param status the {@link Saml2ErrorStatus}
   * @param msg the error message (will not be included in the resulting {@code Status} message)
   */
  public Saml2ErrorStatusException(final Saml2ErrorStatus status, final String msg) {
    this(status, msg, null);
  }

  /**
   * Constructor.
   * 
   * @param status the {@link Saml2ErrorStatus}
   * @param cause the cause of the error
   */
  public Saml2ErrorStatusException(final Saml2ErrorStatus status, final Throwable cause) {
    this(status, status.getDefaultStatusMessage(), cause);
  }

  /**
   * Constructor.
   * 
   * @param status the {@link Saml2ErrorStatus}
   * @param msg the error message (will not be included in the resulting {@code Status} message)
   * @param cause the cause of the error
   */
  public Saml2ErrorStatusException(final Saml2ErrorStatus status, final String msg, final Throwable cause) {
    this(status.getStatusCode(), status.getSubStatusCode(), status.getStatusMessageCode(),
        status.getDefaultStatusMessage(), msg, cause);
  }

  /**
   * Constructor.
   * 
   * @param statusCode the main status code
   * @param subStatusCode the subordinate status code
   * @param statusMessageCode the status message code (will be resolved against a {@link MessageSource})
   * @param defaultStatusMessage the status message to use if the {@code statusMessageCode} can not be resolved against
   *          a {@link MessageSource}
   */
  public Saml2ErrorStatusException(final String statusCode, final String subStatusCode,
      final String statusMessageCode, final String defaultStatusMessage) {
    this(statusCode, subStatusCode, statusMessageCode, defaultStatusMessage, defaultStatusMessage, null);
  }

  /**
   * Constructor.
   * 
   * @param statusCode the main status code
   * @param subStatusCode the subordinate status code
   * @param statusMessageCode the status message code (will be resolved against a {@link MessageSource}
   * @param defaultStatusMessage the status message to use if the {@code statusMessageCode} can not be resolved against
   *          a {@link MessageSource}
   * @param msg the error message (will not be included in the resulting {@code Status} message)
   */
  public Saml2ErrorStatusException(final String statusCode, final String subStatusCode,
      final String statusMessageCode, final String defaultStatusMessage, final String msg) {
    this(statusCode, subStatusCode, statusMessageCode, defaultStatusMessage, msg, null);
  }

  /**
   * Constructor.
   * 
   * @param statusCode the main status code
   * @param subStatusCode the subordinate status code
   * @param statusMessageCode the status message code (will be resolved against a {@link MessageSource}
   * @param defaultStatusMessage the status message to use if the {@code statusMessageCode} can not be resolved against
   *          a {@link MessageSource}
   * @param cause the cause of the error
   */
  public Saml2ErrorStatusException(final String statusCode, final String subStatusCode,
      final String statusMessageCode, final String defaultStatusMessage, final Throwable cause) {
    this(statusCode, subStatusCode, statusMessageCode, defaultStatusMessage, defaultStatusMessage, cause);
  }

  /**
   * Constructor.
   * 
   * @param statusCode the main status code
   * @param subStatusCode the subordinate status code
   * @param statusMessageCode the status message code (will be resolved against a {@link MessageSource}
   * @param defaultStatusMessage the status message to use if the {@code statusMessageCode} can not be resolved against
   *          a {@link MessageSource}
   * @param msg the error message (will not be included in the resulting {@code Status} message)
   * @param cause the cause of the error
   */
  public Saml2ErrorStatusException(final String statusCode, final String subStatusCode,
      final String statusMessageCode, final String defaultStatusMessage, final String msg, final Throwable cause) {
    super(msg, cause);
    this.statusCode = Objects.requireNonNull(statusCode, "statusCode must not be null");
    this.subStatusCode = Objects.requireNonNull(subStatusCode, "subStatusCode must not be null");
    this.statusMessageCode = statusMessageCode;
    this.defaultStatusMessage = Objects.requireNonNull(defaultStatusMessage, "defaultStatusMessage must not be null");
  }

  /**
   * Assigns a custom status message. May be used if the exception object is initialized using a
   * {@link Saml2ErrorStatus} object.
   * 
   * @param statusMessageCode the status message code (for resolving against a {@link MessageSource}
   * @param defaultStatusMessage the default status message (if resolving fails)
   */
  public void setCustomStatusMessage(final String statusMessageCode, final String defaultStatusMessage) {
    this.statusMessageCode = Objects.requireNonNull(statusMessageCode, "statusMessageCode must not be null");
    this.defaultStatusMessage = Objects.requireNonNull(defaultStatusMessage, "defaultStatusMessage must not be null");
  }

  /**
   * Assigns a custom status message. If a {@link MessageSource} is being used when obtaining the {@code Status} use
   * {@link #setCustomStatusMessage(String, String)} instead.
   * 
   * @param statusMessage the status message
   */
  public void setCustomStatusMessage(final String statusMessage) {
    this.defaultStatusMessage = Objects.requireNonNull(statusMessage, "statusMessage must not be null");
  }

  /**
   * Gets a SAML v2 {@code Status} element given this exception.
   *
   * @return a Status element
   */
  public Status getStatus() {
    return this.getStatus(null, null);
  }

  /**
   * Gets a SAML v2 {@code Status} element given this exception.
   * 
   * @param messageSource the message source to use when resolving the status message (if null, the
   *          {@code defaultStatusMessage} will be used)
   * @param locale the locale to use when resolving the status message
   * @return a Status element
   */
  public Status getStatus(final MessageSource messageSource, final Locale locale) {
    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode sc = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    sc.setValue(this.statusCode);

    final StatusCode ssc = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    ssc.setValue(this.subStatusCode);
    sc.setStatusCode(ssc);

    status.setStatusCode(sc);

    String statusMessage = null;

    if (messageSource != null && StringUtils.hasText(this.statusMessageCode)) {
      try {
        statusMessage = messageSource.getMessage(this.statusMessageCode, null, this.defaultStatusMessage, locale);
      }
      catch (NoSuchMessageException e) {
      }
    }
    if (statusMessage == null) {
      statusMessage = this.defaultStatusMessage;
    }

    if (statusMessage != null) {
      final StatusMessage sm = (StatusMessage) XMLObjectSupport.buildXMLObject(StatusMessage.DEFAULT_ELEMENT_NAME);
      sm.setValue(statusMessage);
      status.setStatusMessage(sm);
    }
    return status;
  }

}
