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

/**
 * Constants for all audit event types produced for credentials monitoring.
 *
 * @author Martin Lindström
 */
public enum CredentialAuditEvents {

  /** A test of a monitored credential failed. */
  CREDENTIAL_AUDIT_TEST_ERROR("CREDENTIAL_TEST_ERROR"),

  /** A credential test failed, but the reload of the same credential was successful. */
  CREDENTIAL_AUDIT_RELOAD_SUCCESS("CREDENTIAL_RELOAD_SUCCESS"),

  /** A credential test failed, and later when the credential was reloaded, this also failed. */
  CREDENTIAL_AUDIT_RELOAD_ERROR("CREDENTIAL_RELOAD_ERROR");

  /** The event type name. */
  private final String typeName;

  /**
   * Constructor.
   *
   * @param typeName the event type name
   */
  CredentialAuditEvents(final String typeName) {
    this.typeName = typeName;
  }

  /**
   * Gets the event type name.
   *
   * @return the event type name
   */
  public String getTypeName() {
    return this.typeName;
  }
}
