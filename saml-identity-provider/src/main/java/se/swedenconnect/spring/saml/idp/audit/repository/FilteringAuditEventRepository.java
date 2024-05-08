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

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * Abstract {@link AuditEventRepository} that supports filtering of events.
 *
 * @author Martin Lindström
 */
@Slf4j
public abstract class FilteringAuditEventRepository implements AuditEventRepository {

  /** The filter. */
  private final Predicate<AuditEvent> filter;

  /**
   * Constructor setting up a filter that accepts all events.
   */
  public FilteringAuditEventRepository() {
    this(null);
  }

  /**
   * Constructor.
   *
   * @param filter the filter
   */
  public FilteringAuditEventRepository(final Predicate<AuditEvent> filter) {
    this.filter = Optional.ofNullable(filter).orElseGet(() -> inclusionPredicate(Collections.emptyList()));
  }

  /** {@inheritDoc} */
  @Override
  public final void add(final AuditEvent event) {
    if (event != null) {
      if (this.filter.test(event)) {
        log.debug("Audit logging event '{}' for principal '{}' ...", event.getType(), event.getPrincipal());
        this.addEvent(event);
      }
      else {
        log.debug("Audit event {} not logged - filter rules excludes it", event.getType());
      }
    }
  }

  /**
   * Logs an event.
   *
   * @param event the audit event to log
   */
  protected abstract void addEvent(final AuditEvent event);

  /**
   * Returns an audit event filter that accepts a list of event types that are accepted.
   * <p>
   * If the {@code types} parameter is {@code null} or an empty list, all events are accepted.
   * </p>
   *
   * @param types the types that are accepted
   * @return a {@link Predicate} that returns {@code true} if an event should be audited
   */
  public static Predicate<AuditEvent> inclusionPredicate(final List<String> types) {
    return event -> {
      if (types == null || types.isEmpty()) {
        return true;
      }
      return types.contains(event.getType());
    };
  }

  /**
   * Returns an audit event filter that excludes the given event types from being audited.
   * <p>
   * If the {@code types} parameter is {@code null} or an empty list, no events are excluded.
   * </p>
   *
   * @param types the types to exclude
   * @return a {@link Predicate} that returns {@code true} if an event should be audited
   */
  public static Predicate<AuditEvent> exclusionPredicate(final List<String> types) {
    return event -> {
      if (types == null) {
        return true;
      }
      return !types.contains(event.getType());
    };
  }

  /**
   * Returns an audit event filter that combines {@code inclusionExclusionPredicate(List, List)} and
   * {@link #exclusionPredicate(List)}.
   *
   * @param includeTypes the types to include (if {@code null} or empty, all events are accepted)
   * @param dontIncludeTypes the types to exclude (if {@code null} or empty, no events are excluded)
   * @return a {@link Predicate} that returns {@code true} if an event should be audited
   */
  public static Predicate<AuditEvent> inclusionExclusionPredicate(
      final List<String> includeTypes, final List<String> dontIncludeTypes) {
    return inclusionPredicate(includeTypes).and(exclusionPredicate(dontIncludeTypes));
  }

}
