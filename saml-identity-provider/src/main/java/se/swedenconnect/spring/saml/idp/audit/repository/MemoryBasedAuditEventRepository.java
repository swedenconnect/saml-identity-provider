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
import java.util.List;
import java.util.function.Predicate;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.actuate.audit.InMemoryAuditEventRepository;
import org.springframework.util.Assert;

/**
 * An in-memory {@link AuditEventRepository} that adds filtering support (compared to
 * {@link InMemoryAuditEventRepository}).
 *
 * @author Martin Lindström
 */
public class MemoryBasedAuditEventRepository extends FilteringAuditEventRepository {

  public static final int DEFAULT_CAPACITY = 1000;

  private final InMemoryAuditEventRepository repository;

  /**
   * Constructor setting up a memory based {@link AuditEventRepository} that logs all events and has a capacity of
   * {@value #DEFAULT_CAPACITY}.
   */
  public MemoryBasedAuditEventRepository() {
    this(null, DEFAULT_CAPACITY);
  }

  /**
   * Constructor setting up a memory based {@link AuditEventRepository} that logs events determined by the supplied
   * filter and has a capacity of {@value #DEFAULT_CAPACITY}.
   *
   * @param filter for determining which events to log
   */
  public MemoryBasedAuditEventRepository(final Predicate<AuditEvent> filter) {
    this(filter, DEFAULT_CAPACITY);
  }

  /**
   * Constructor setting up a memory based {@link AuditEventRepository} that logs events determined by the supplied
   * filter and has a capacity given by {@code capacity}.
   *
   * @param filter for determining which events to log
   * @param capacity the capacity for the number of events that should be saved
   */
  public MemoryBasedAuditEventRepository(final Predicate<AuditEvent> filter, final int capacity) {
    super(filter);
    Assert.isTrue(capacity > 0, "Invalid capacity - must be greater than 0");
    this.repository = new InMemoryAuditEventRepository(capacity);
  }

  /** {@inheritDoc} */
  @Override
  protected void addEvent(final AuditEvent event) {
    this.repository.add(event);
  }

  /** {@inheritDoc} */
  @Override
  public List<AuditEvent> find(final String principal, final Instant after, final String type) {
    return this.repository.find(principal, after, type);
  }

}
