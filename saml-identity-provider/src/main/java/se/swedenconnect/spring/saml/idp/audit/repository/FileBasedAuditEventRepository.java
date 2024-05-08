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

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * A write-only {@link AuditEventRepository} that writes audit events to a file.
 *
 * @author Martin Lindström
 */
@Slf4j
public class FileBasedAuditEventRepository extends FilteringAuditEventRepository {

  /** The audit logger (Java Util Logging logger). */
  private final java.util.logging.Logger auditLogger;

  /** For mapping events to strings. */
  private final AuditEventMapper eventMapper;

  /**
   * Constructor mapping to {@link #FileBasedAuditEventRepository(String, AuditEventMapper, Predicate)} where the filter
   * allows all events.
   *
   * @param logFile the log file including its path
   * @param eventMapper the event mapper used to map events to strings
   * @throws IOException if the logfile is invalid
   */
  public FileBasedAuditEventRepository(final String logFile, final AuditEventMapper eventMapper) throws IOException {
    this(logFile, eventMapper, null);
  }

  /**
   * Constructor.
   *
   * @param logFile the log file including its path
   * @param eventMapper the event mapper used to map events to strings
   * @param filter filter for determining which events to log
   * @throws IOException if the logfile is invalid
   */
  public FileBasedAuditEventRepository(
      final String logFile, final AuditEventMapper eventMapper, final Predicate<AuditEvent> filter)
      throws IOException {
    super(filter);
    this.eventMapper = Objects.requireNonNull(eventMapper, "eventMapper must not be null");

    final DateRollingFileHandler handler = new DateRollingFileHandler(logFile);

    // Build the logger name based on the log file name ...
    final String loggerName = Path.of(logFile).toAbsolutePath().toString();

    this.auditLogger = Logger.getLogger(loggerName);
    this.auditLogger.setLevel(Level.INFO);
    this.auditLogger.addHandler(handler);
    this.auditLogger.setUseParentHandlers(false);
  }

  /** {@inheritDoc} */
  @Override
  public void addEvent(final AuditEvent event) {
    try {
      this.auditLogger.log(Level.INFO, this.eventMapper.write(event));
    }
    catch (final Throwable e) {
      log.error("Failed to audit log to file - {}", e.getMessage(), e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<AuditEvent> find(final String principal, final Instant after, final String type) {
    return Collections.emptyList();
  }

}
