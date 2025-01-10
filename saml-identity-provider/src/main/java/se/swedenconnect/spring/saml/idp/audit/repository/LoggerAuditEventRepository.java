/*
 * Copyright 2023-2025 Sweden Connect
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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.springframework.boot.actuate.audit.AuditEvent;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * A {@link org.springframework.boot.actuate.audit.AuditEventRepository AuditEventRepository} that logs to a named
 * logger.
 *
 * @author Martin Lindström
 */
@Slf4j
public class LoggerAuditEventRepository extends FilteringAuditEventRepository {

  /** The logger. */
  private final Logger auditLogger;

  /** The log level to use. */
  private final Level auditLogLevel;

  /** The event mapper. */
  private final AuditEventMapper eventMapper;

  /**
   * Constructor mapping to {@link #LoggerAuditEventRepository(String, Level, AuditEventMapper, Predicate)} where the
   * filter allows all events.
   *
   * @param loggerName the name of the logger
   * @param logLevel the log level to use (INFO is defaylt)
   * @param eventMapper the event mapper used to map events to strings
   */
  public LoggerAuditEventRepository(@Nonnull final String loggerName, @Nullable final Level logLevel,
      @Nonnull final AuditEventMapper eventMapper) {
    this(loggerName, logLevel, eventMapper, null);
  }

  /**
   * Constructor.
   *
   * @param loggerName the name of the logger
   * @param logLevel the log level to use (INFO is defaylt)
   * @param eventMapper the event mapper used to map events to strings
   * @param filter filter for determining which events to log
   */
  public LoggerAuditEventRepository(@Nonnull final String loggerName, @Nullable final Level logLevel,
      @Nonnull final AuditEventMapper eventMapper, @Nullable final Predicate<AuditEvent> filter) {
    super(filter);
    this.auditLogger = LoggerFactory.getLogger(Objects.requireNonNull(loggerName, "loggerName must not be null"));
    this.auditLogLevel = Optional.ofNullable(logLevel).orElse(Level.INFO);
    this.eventMapper = Objects.requireNonNull(eventMapper, "eventMapper must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void addEvent(final AuditEvent event) {
    try {
      log.debug("Audit logging event '{}' for principal '{}' ...", event.getType(), event.getPrincipal());
      this.auditLogger.atLevel(this.auditLogLevel).log(this.eventMapper.write(event));
    }
    catch (final Throwable e) {
      log.error("Failed to audit log to file - {}", e.getMessage(), e);
    }
  }

  /**
   * Will always return an empty list.
   */
  @Override
  public List<AuditEvent> find(final String principal, final Instant after, final String type) {
    return Collections.emptyList();
  }
}
