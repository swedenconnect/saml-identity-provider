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
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

import java.io.Serial;

/**
 * Audit data for unrecoverable errors that are reported in the UI.
 *
 * @author Martin Lindström
 */
@JsonInclude(Include.NON_EMPTY)
public class Saml2UnrecoverableErrorAuditData extends Saml2AuditData {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The error code. */
  @Getter
  @Setter
  @JsonProperty(value = "error-code")
  private String errorCode;

  /** The error message. */
  @Getter
  @Setter
  @JsonProperty(value = "error-message")
  private String errorMessage;

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "unrecoverable-error";
  }

  /**
   * Creates a {@link Saml2UnrecoverableErrorAuditData} given a {@link UnrecoverableSaml2IdpException}.
   *
   * @param error the exception
   * @return a {@link Saml2UnrecoverableErrorAuditData}
   */
  public static Saml2UnrecoverableErrorAuditData of(final UnrecoverableSaml2IdpException error) {
    if (error == null) {
      return null;
    }
    final Saml2UnrecoverableErrorAuditData data = new Saml2UnrecoverableErrorAuditData();
    data.setErrorCode(error.getError().getMessageCode());
    data.setErrorMessage(error.getMessage());

    return data;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("error-code='%s', error-message='%s'", this.errorCode, this.errorMessage);
  }

}
