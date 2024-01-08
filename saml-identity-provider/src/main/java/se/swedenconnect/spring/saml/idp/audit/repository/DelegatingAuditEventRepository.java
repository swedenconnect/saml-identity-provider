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
package se.swedenconnect.spring.saml.idp.audit.repository;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * A delegating {@link AuditEventRepository} that can be used to support multiple {@link AuditEventRepository}
 * instances.
 * <p>
 * Note that when invoking {@link #find(String, Instant, String)}, the first installed repository will be tried, and if
 * that repository returns an empty list, the next repository will be tried.
 * </p>
 *
 * @author Martin Lindström
 */
@Slf4j
public class DelegatingAuditEventRepository implements AuditEventRepository {

  /** The underlying {@link AuditEventRepository} instances. */
  private final List<AuditEventRepository> repositories;

  /**
   * Constructor.
   *
   * @param repositories the underlying {@link AuditEventRepository} instances.
   */
  public DelegatingAuditEventRepository(final List<AuditEventRepository> repositories) {
    this.repositories = Objects.requireNonNull(repositories, "repositories must not be null");
  }

  /**
   * Adds the event to all installed repositories.
   */
  @Override
  public void add(final AuditEvent event) {
    this.repositories.forEach(r -> {
      try {
        r.add(event);
      }
      catch (final Exception e) {
        log.error("Failed to add event to {}", r.getClass().getSimpleName(), e);
      }
    });
  }

  /**
   * The first installed repository will be tried, and if that repository returns an empty list, the next repository
   * will be tried, and so on.
   */
  @Override
  public List<AuditEvent> find(final String principal, final Instant after, final String type) {
    for (final AuditEventRepository r : this.repositories) {
      final List<AuditEvent> events = r.find(principal, after, type);
      if (events != null && !events.isEmpty()) {
        return events;
      }
    }
    return Collections.emptyList();
  }

}
