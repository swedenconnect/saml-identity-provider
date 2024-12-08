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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.springframework.boot.actuate.audit.AuditEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.AbstractCredentialMonitoringEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import java.io.Serial;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Audit event for creating event objects concerning credentials monitoring. See <a
 * href="https://docs.swedenconnect.se/credentials-support/#monitoring">Credentials monitoring</a>.
 *
 * @author Martin Lindström
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class CredentialAuditEvent extends AuditEvent {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** Symbolic constant for system principal. */
  public static final String SYSTEM_PRINCIPAL = "system";

  /**
   * Constructor
   *
   * @param type the audit type
   * @param timestamp the timestamp
   * @param auditData the audit data
   */
  protected CredentialAuditEvent(@Nonnull final CredentialAuditEvents type, final long timestamp,
      @Nonnull final Map<String, Object> auditData) {
    super(Instant.ofEpochMilli(timestamp), SYSTEM_PRINCIPAL, type.getTypeName(), auditData);
  }

  /**
   * Transforms a credential monitoring event into an audit event.
   *
   * @param event the event to transform
   * @param <T> the credential monitoring event type
   * @return a {@link CredentialAuditEvent}
   */
  public static <T extends AbstractCredentialMonitoringEvent> CredentialAuditEvent of(@Nonnull final T event) {
    if (event instanceof final FailedCredentialTestEvent e) {
      return new CredentialAuditEvent(CredentialAuditEvents.CREDENTIAL_AUDIT_TEST_ERROR, e.getTimestamp(),
          buildAuditData(e.getCredentialName(), e.getError(), e.getException()));
    }
    else if (event instanceof final SuccessfulCredentialReloadEvent e) {
      return new CredentialAuditEvent(CredentialAuditEvents.CREDENTIAL_AUDIT_RELOAD_SUCCESS, e.getTimestamp(),
          buildAuditData(e.getCredentialName(), null, null));
    }
    else if (event instanceof final FailedCredentialReloadEvent e) {
      return new CredentialAuditEvent(CredentialAuditEvents.CREDENTIAL_AUDIT_RELOAD_ERROR, e.getTimestamp(),
          buildAuditData(e.getCredentialName(), e.getError(), e.getException()));
    }
    else {
      throw new IllegalArgumentException("Unsupported audit event type: " + event.getClass().getName());
    }
  }

  /**
   * Builds a {@link Map} given the supplied audit data
   *
   * @param credentialName name of credential
   * @param errorMsg the error message
   * @param exception the exception name
   * @return a {@link Map} of audit data
   */
  private static Map<String, Object> buildAuditData(
      @Nonnull final String credentialName, @Nullable final String errorMsg, @Nullable final String exception) {
    final Map<String, Object> auditData = new HashMap<>();
    auditData.put("credential-name", credentialName);
    if (errorMsg != null || exception != null) {
      final Map<String, String> error = new HashMap<>();
      auditData.put("error", error);
      Optional.ofNullable(errorMsg).ifPresent(e -> error.put("message", e));
      Optional.ofNullable(exception).ifPresent(e -> error.put("exception", e));
    }
    return auditData;
  }

  /**
   * Gets a string suitable to include in log entries.
   *
   * @return a log string
   */
  @JsonIgnore
  public String getLogString() {
    final StringBuffer sb = new StringBuffer("type='%s', credential-name='%s'"
        .formatted(this.getType(), this.getData().get("credential-name")));
    Optional.ofNullable(this.getData().get("error")).ifPresent(e -> sb.append(", error='").append(e).append("'"));
    Optional.ofNullable(this.getData().get("exception"))
        .ifPresent(e -> sb.append(", exception='").append(e).append("'"));
    return sb.toString();
  }

}
