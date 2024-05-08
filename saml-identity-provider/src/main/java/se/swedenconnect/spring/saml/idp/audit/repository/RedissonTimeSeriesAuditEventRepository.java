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
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import org.redisson.api.RedissonClient;
import org.redisson.api.TimeSeriesEntry;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * An {@link AuditEventRepository} implementation that uses Redis time series to store events.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@Slf4j
public class RedissonTimeSeriesAuditEventRepository extends FilteringAuditEventRepository {

  /** The Redis client. */
  private final RedissonClient client;

  /** The Redis timeseries name holding the audit events. */
  private final String tsName;

  /** The audit event mapper. */
  private final AuditEventMapper eventMapper;

  /**
   * Constructor setting up the repository to log all events.
   *
   * @param client the Redis client
   * @param tsName the Redis timeseries name holding the audit events
   * @param mapper mapper for creating/reading JSON events
   */
  public RedissonTimeSeriesAuditEventRepository(final RedissonClient client, final String tsName,
      final AuditEventMapper mapper) {
    this(client, tsName, mapper, null);
  }

  /**
   * Constructor setting up the repository to log events according to the supplied filter.
   *
   * @param client the Redis client
   * @param tsName the Redis timeseries name holding the audit events
   * @param mapper mapper for creating/reading JSON events
   * @param filter filter for determining which events to log
   */
  public RedissonTimeSeriesAuditEventRepository(final RedissonClient client, final String tsName,
      final AuditEventMapper mapper, final Predicate<AuditEvent> filter) {
    super(filter);
    this.client = Objects.requireNonNull(client, "client must not be null");
    this.tsName = "%s:%s".formatted(Objects.requireNonNull(tsName, "keyName must not be null"), "timeseries");
    this.eventMapper = Objects.requireNonNull(mapper, "mapper must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void addEvent(final AuditEvent event) {
    try {
      this.client.getTimeSeries(this.tsName)
          .add(event.getTimestamp().toEpochMilli(), this.eventMapper.write(event));
    }
    catch (final Throwable e) {
      log.error("Failed to write event '{}' to Redis timeseries {}", event.getType(), this.tsName, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<AuditEvent> find(final String principal, final Instant after, final String type) {
    final Collection<TimeSeriesEntry<Object, Object>> timeSeries =
        this.client.getTimeSeries(this.tsName).entryRange(
            Optional.ofNullable(after)
                .orElse(Instant.EPOCH)
                .toEpochMilli(),
            Instant.now().plus(1, ChronoUnit.MINUTES).toEpochMilli());

    return timeSeries.stream()
        .map(e -> this.eventMapper.read((String) e.getValue()))
        .filter(e -> type == null || type.equals(e.getType()))
        .filter(e -> principal == null || principal.equals(e.getPrincipal()))
        .toList();
  }

}
