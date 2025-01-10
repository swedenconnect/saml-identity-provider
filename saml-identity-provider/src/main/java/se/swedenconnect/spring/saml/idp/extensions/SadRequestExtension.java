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

import org.springframework.util.Assert;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADRequest;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import java.io.Serial;
import java.io.Serializable;

/**
 * A representation of the {@code SADRequest} extension as defined in
 * <a
 * href="https://docs.swedenconnect.se/technical-framework/updates/13_-_Signature_Activation_Protocol.html">Signature
 * Activation Protocol for Federated Signing</a>.
 *
 * @author Martin Lindström
 */
public class SadRequestExtension implements Serializable {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The ID of the SADRequest. */
  private final String id;

  /** The requester ID. */
  private final String requesterId;

  /** The ID for the corresponding SignRequest. */
  private final String signRequestId;

  /** Number of documents to sign. */
  private final Integer documentCount;

  /**
   * Constructor.
   * <p>
   * Note: No validation of the {@link SADRequest} is made.
   * </p>
   *
   * @param sadRequest the {@link SADRequest} extension
   */
  public SadRequestExtension(final SADRequest sadRequest) {
    Assert.notNull(sadRequest, "sadRequest must not be null");
    this.id = sadRequest.getID();
    this.requesterId = sadRequest.getRequesterID();
    this.signRequestId = sadRequest.getSignRequestID();
    this.documentCount = sadRequest.getDocCount();
  }

  /**
   * Gets the ID of the {@link SADRequest}.
   *
   * @return the ID of the {@link SADRequest}
   */
  public String getId() {
    return this.id;
  }

  /**
   * Gets the requester ID.
   *
   * @return the requester ID
   */
  public String getRequesterId() {
    return this.requesterId;
  }

  /**
   * Gets the sign request ID.
   *
   * @return the sign request ID
   */
  public String getSignRequestId() {
    return this.signRequestId;
  }

  /**
   * Gets the document count.
   *
   * @return the document count
   */
  public Integer getDocumentCount() {
    return this.documentCount;
  }

}
