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
package se.swedenconnect.spring.saml.idp.extensions;

import java.io.Serial;
import java.io.Serializable;
import java.util.Optional;

import org.springframework.util.StringUtils;

import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessageMimeTypeEnum;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * A representation of the {@code SignMessage} extension as specified in section 3.1.2 of <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
 * Extension for Federated Central Signing Services</a>.
 * <p>
 * The {code SignatureMessageExtension} holds the decrypted version of a {@link SignMessage} object.
 * </p>
 * 
 * @author Martin Lindström
 */
public class SignatureMessageExtension implements Serializable {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * The base64 encoded sign message in unencrypted form. The message MUST be encoded using UTF-8.
   */
  private final String message;

  /**
   * The MIME type of the sign message. Defaults to {@link SignMessageMimeTypeEnum#TEXT}.
   */
  private final SignMessageMimeTypeEnum mimeType;

  /**
   * If {@code true}, the caller has indicated that the sign message MUST be displayed for the user. If not the
   * operation must not proceed.
   */
  private final boolean mustShow;

  /**
   * If a {@link SignatureMessagePreprocessor} is installed, the {@code processedMessage} will contain the result from
   * this processing, i.e., a string that is prepared for display (on a web page, on a device, ...).
   */
  private String processedMessage;

  /**
   * Constructor.
   * 
   * @param message the unencrypted sign message (in base64)
   * @param mimeType the message MIME type - if {@code null}, {@link SignMessageMimeTypeEnum#TEXT} is assumed
   * @param mustShow whether the caller has indicated that the sign message MUST be displayed for the user
   */
  public SignatureMessageExtension(
      final String message, final SignMessageMimeTypeEnum mimeType, final Boolean mustShow) {
    this.message = Optional.ofNullable(message).filter(StringUtils::hasText)
        .orElseThrow(() -> new IllegalArgumentException("message must be set"));
    this.mimeType = Optional.ofNullable(mimeType).orElse(SignMessageMimeTypeEnum.TEXT);
    this.mustShow = Optional.ofNullable(mustShow).orElse(false);
  }

  /**
   * Gets the (base64 encoded) sign message.
   * 
   * @return the sign message
   */
  public String getMessage() {
    return this.message;
  }

  /**
   * Gets the MIME type of the sign message. Defaults to {@link SignMessageMimeTypeEnum#TEXT}.
   * 
   * @return the sign message MIME type
   */
  public SignMessageMimeTypeEnum getMimeType() {
    return this.mimeType;
  }

  /**
   * Whether the caller has indicated that the sign message MUST be displayed for the user.
   * 
   * @return {@code true} if the message must be displayed for the user and {@code false} otherwise
   */
  public boolean isMustShow() {
    return this.mustShow;
  }

  /**
   * Gets the processed message. If a {@link SignatureMessagePreprocessor} is installed, the
   * {@code processedMessage} will contain the result from this processing, i.e., a string that is prepared for display
   * (on a web page, on a device, ...).
   * 
   * @return a message prepared for display
   */
  public String getProcessedMessage() {
    return this.processedMessage;
  }

  /**
   * Assigns the processed message. If a {@link SignatureMessagePreprocessor} is installed, the
   * {@code processedMessage} will contain the result from this processing, i.e., a string that is prepared for display
   * (on a web page, on a device, ...).
   * 
   * @param processedMessage a message prepared for display
   */
  public void setProcessedMessage(final String processedMessage) {
    this.processedMessage = processedMessage;
  }

}
