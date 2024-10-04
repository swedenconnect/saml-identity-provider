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
package se.swedenconnect.spring.saml.idp.audit.data;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Optional;

/**
 * Audit data representing a SAML response.
 *
 * @author Martin Lindström
 */
@JsonInclude(Include.NON_EMPTY)
public class Saml2ResponseAuditData extends Saml2AuditData {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The Response ID. */
  @Getter
  @Setter
  @JsonProperty(value = "id")
  private String id;

  /** The ID matching the AuthnRequest ID. */
  @Getter
  @Setter
  @JsonProperty(value = "in-response-to")
  private String inResponseTo;

  /** The status. */
  @Getter
  @Setter
  @JsonProperty(value = "status")
  private SamlStatus status;

  /** The response issuance time. */
  @Getter
  @Setter
  @JsonProperty(value = "issued-at")
  private Instant issuedAt;

  /** The destination, i.e., where the response is being sent. */
  @Getter
  @Setter
  @JsonProperty(value = "destination")
  private String destination;

  /** Tells whether the response is signed. */
  @Getter
  @Setter
  @JsonProperty(value = "is-signed")
  private boolean signed;

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "saml-response";
  }

  /**
   * Creates a {@link Saml2ResponseAuditData} given a {@link Response} object.
   *
   * @param response the SAML response
   * @return a {@link Saml2ResponseAuditData}
   */
  public static Saml2ResponseAuditData of(final Response response) {
    if (response == null) {
      return null;
    }
    final Saml2ResponseAuditData data = new Saml2ResponseAuditData();
    data.setId(response.getID());
    data.setInResponseTo(response.getInResponseTo());
    final Status status = response.getStatus();
    if (status != null) {
      final SamlStatus samlStatus = new SamlStatus();
      samlStatus.setStatusCode(Optional.ofNullable(status.getStatusCode()).map(StatusCode::getValue).orElse(null));
      samlStatus.setSubordinateStatusCode(Optional.ofNullable(status.getStatusCode())
          .map(StatusCode::getStatusCode)
          .map(StatusCode::getValue)
          .orElse(null));
      samlStatus.setStatusMessage(Optional.ofNullable(status.getStatusMessage())
          .map(StatusMessage::getValue)
          .orElse(null));
      data.setStatus(samlStatus);
    }
    data.setIssuedAt(response.getIssueInstant());
    data.setDestination(response.getDestination());
    data.setSigned(response.isSigned());

    return data;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format(
        "id='%s', in-response-to='%s', status=[%s], issued-at='%s', destination='%s', signed='%s']", this.id,
        this.inResponseTo, this.status, this.issuedAt, this.destination, this.signed);
  }

  /**
   * Represents a SAML {@code Status}.
   */
  @JsonInclude(Include.NON_EMPTY)
  public static class SamlStatus implements Serializable {

    @Serial
    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /** The main status code. */
    @Getter
    @Setter
    @JsonProperty(value = "code")
    private String statusCode;

    /** The subordinate status code. */
    @Getter
    @Setter
    @JsonProperty(value = "subordinate-code")
    private String subordinateStatusCode;

    /** The status message. */
    @Getter
    @Setter
    @JsonProperty(value = "message")
    private String statusMessage;

    /** {@inheritDoc} */
    @Override
    public String toString() {
      final StringBuilder sb = new StringBuilder("code='");
      sb.append(this.statusCode).append("'");

      if (this.subordinateStatusCode != null) {
        sb.append(", subordinate-code='").append(this.subordinateStatusCode).append("'");
      }
      if (this.statusMessage != null) {
        sb.append("', message='").append(this.statusMessage).append("'");
      }
      return sb.toString();
    }

  }

}
