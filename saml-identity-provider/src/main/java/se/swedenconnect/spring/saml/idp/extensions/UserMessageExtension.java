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
package se.swedenconnect.spring.saml.idp.extensions;

import org.opensaml.core.xml.schema.XSBase64Binary;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.InvalidMimeTypeException;
import org.springframework.util.MimeType;
import org.springframework.util.StringUtils;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.UserMessage;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Representation of a {@code UserMessage}, see <a
 * href="https://docs.swedenconnect.se/technical-framework/updates/18_-_User_Message_Extension_in_SAML_Authentication_Requests.html">User
 * Message Extension in SAML Authentication Requests</a>.
 *
 * @author Martin Lindström
 */
public class UserMessageExtension implements Serializable {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** Symbolic constant used to specify that no language was given. */
  public static final String NO_LANG = "NO_LANG";

  /** The MIME type of the messages. */
  private final MimeType mimeType;

  /** Mapping of country codes and Base64 encoded messages. */
  private final Map<String, String> messages;

  /**
   * If a {@link UserMessagePreprocessor} is installed, the {@code processedMessages} will contain the result from this
   * processing, i.e., strings that are prepared for display (on a web page, on a device, ...).
   */
  private Map<String, String> processedMessages;

  /**
   * Constructor.
   *
   * @param userMessage a {@link UserMessage} object
   * @throws InvalidMimeTypeException if the supplied MIME type is invalid
   */
  public UserMessageExtension(@NonNull final UserMessage userMessage) throws InvalidMimeTypeException {
    this.mimeType = MimeType.valueOf(Optional.ofNullable(userMessage.getMimeType())
        .orElse(UserMessage.DEFAULT_MIME_TYPE));
    this.messages = userMessage.getMessages().stream()
        .filter(m -> StringUtils.hasText(m.getValue()))
        .collect(Collectors.toMap(m -> Optional.ofNullable(m.getXMLLang()).orElse(NO_LANG), XSBase64Binary::getValue));
  }

  /**
   * Gets the MIME type for the messages.
   *
   * @return the MIME type
   */
  @NonNull
  public MimeType getMimeType() {
    return this.mimeType;
  }

  /**
   * Gets the messages contained within the {@code UserMessage} extension.
   * <p>
   * Each entry of the returned {@link Map} holds the language code as the key and the Base64 encoded message as the
   * value. Note {@value #NO_LANG} will be used as key if no language was specified.
   * </p>
   *
   * @return a {@link Map} of language codes and Base64 encoded messages
   */
  @NonNull
  public Map<String, String> getMessages() {
    return Collections.unmodifiableMap(this.messages);
  }

  /**
   * Gets the processed messages. If a {@link UserMessagePreprocessor} is installed, the {@code processedMessages} will
   * contain the result from this processing, i.e., strings that are prepared for display (on a web page, on a device,
   * ...).
   *
   * @return messages ready for displaying, or {@code null} if the messages haven't been processed
   */
  @Nullable
  public Map<String, String> getProcessedMessages() {
    return this.processedMessages;
  }

  /**
   * Assigns the processed messages. If a {@link UserMessagePreprocessor} is installed, the {@code processedMessages}
   * will contain the result from this processing, i.e., strings that are prepared for display (on a web page, on a
   * device, ...).
   *
   * @param processedMessages processed messages
   */
  public void setProcessedMessages(@NonNull final Map<String, String> processedMessages) {
    this.processedMessages = processedMessages;
  }

}
