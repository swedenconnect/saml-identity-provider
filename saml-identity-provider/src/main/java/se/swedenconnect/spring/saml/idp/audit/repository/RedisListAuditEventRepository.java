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
import java.util.Optional;
import java.util.function.Predicate;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import lombok.extern.slf4j.Slf4j;

/**
 * An implementation of the {@link AuditEventRepository} that uses Redis lists to store the events.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@Slf4j
public class RedisListAuditEventRepository extends FilteringAuditEventRepository {

  /** The Redis list operations. */
  private final ListOperations<String, String> listOps;

  /** The name of the Redis key holding the audit event list. */
  private final String keyName;

  /** The audit event mapper. */
  private final AuditEventMapper eventMapper;

  /**
   * Constructor setting up the repository to log all events.
   *
   * @param redisTemplate the Redis template
   * @param keyName the name of the Redis key holding the audit event list
   * @param mapper mapper for creating/reading JSON events
   */
  public RedisListAuditEventRepository(final StringRedisTemplate redisTemplate, final String keyName,
      final AuditEventMapper mapper) {
    this(redisTemplate, keyName, mapper, null);
  }

  /**
   * Constructor setting up the repository to log events according to the supplied filter.
   *
   * @param redisTemplate the Redis template
   * @param keyName the name of the Redis key holding the audit event list
   * @param mapper mapper for creating/reading JSON events
   * @param filter filter for determining which events to log
   */
  public RedisListAuditEventRepository(final StringRedisTemplate redisTemplate, final String keyName,
      final AuditEventMapper mapper, final Predicate<AuditEvent> filter) {
    super(filter);
    this.listOps = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null").opsForList();
    this.keyName = "%s:%s".formatted(Objects.requireNonNull(keyName, "keyName must not be null"), "list");
    this.eventMapper = Objects.requireNonNull(mapper, "mapper must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void addEvent(final AuditEvent event) {
    try {
      this.listOps.rightPush(this.keyName, this.eventMapper.write(event));
    }
    catch (final Throwable e) {
      log.error("Failed to write event '{}' to Redis list {}", event.getType(), this.keyName, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<AuditEvent> find(final String principal, final Instant after, final String type) {
    final long size = Optional.ofNullable(this.listOps.size(this.keyName)).orElse(0L);
    final List<String> list = this.listOps.range(this.keyName, 0, size);
    if (list == null) {
      return Collections.emptyList();
    }
    return list.stream()
        .map(e -> this.eventMapper.read(e))
        .filter(e -> type != null ? type.equals(e.getType()) : true)
        .filter(e -> principal != null ? principal.equals(e.getPrincipal()) : true)
        .filter(e -> after != null ? after.isBefore(e.getTimestamp()) : true)
        .toList();
  }
}
