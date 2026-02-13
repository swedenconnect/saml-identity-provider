/*
 * Copyright 2023-2026 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.audit.repository;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.boot.actuate.audit.AuditEvent;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import tools.jackson.databind.ObjectMapper;

import java.io.Serial;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A JSON {@link AuditEventMapper}.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
public class JsonAuditEventMapper implements AuditEventMapper {

  /** The underlying {@link ObjectMapper}. */
  private final ObjectMapper mapper;

  /**
   * Constructor.
   *
   * @param mapper the {@link ObjectMapper}
   */
  public JsonAuditEventMapper(final ObjectMapper mapper) {
    this.mapper = Objects.requireNonNull(mapper, "mapper must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String write(final AuditEvent event) {
    return this.mapper.writerFor(AuditEvent.class).writeValueAsString(event);
  }

  /** {@inheritDoc} */
  @Override
  public AuditEvent read(final String event) {
    return this.mapper.readerFor(JsonAuditEvent.class).<JsonAuditEvent>readValue(event);
  }

  /**
   * Helper class for reading events.
   */
  private static class JsonAuditEvent extends AuditEvent {

    @Serial
    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /**
     * Adds a JsonCreator for Jackson to be able to serialize AuditEvents.
     *
     * @param principal to deserialize
     * @param type to deserialize
     * @param data to deserialize
     */
    @JsonCreator
    public JsonAuditEvent(
        @JsonProperty("principal") final String principal,
        @JsonProperty("type") final String type,
        @JsonProperty("data") final Map<String, Object> data) {
      super(principal, type, Optional.ofNullable(data).orElse(Map.of()));
    }
  }

}
