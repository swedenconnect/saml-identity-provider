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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.audit.AuditEvent;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test cases for LoggerAuditEventRepository.
 *
 * @author Martin Lindström
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LoggerAuditEventRepositoryTest {

  static final String LOGGER_NAME = "AUDIT";
  private MemoryAppender memoryAppender;

  @BeforeAll
  public void setup() {
    this.memoryAppender = new MemoryAppender();
    this.memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());

    final Logger auditLogger = (Logger) LoggerFactory.getLogger(LOGGER_NAME);
    auditLogger.setLevel(Level.INFO);
    auditLogger.addAppender(this.memoryAppender);

    this.memoryAppender.start();
  }

  @Test
  void test() {
    final ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.findAndRegisterModules();
    final AuditEventMapper mapper = new JsonAuditEventMapper(objectMapper);
    final LoggerAuditEventRepository repo = new LoggerAuditEventRepository("AUDIT", null, mapper, null);

    final AuditEvent event = new AuditEvent("kalle", "THE_EVENT_TYPE", Map.of("values", List.of("a", "b")));
    final String eventString = mapper.write(event);

    repo.addEvent(event);

    assertThat(this.memoryAppender.search(Level.INFO))
        .hasSize(1)
        .extracting(ILoggingEvent::toString)
        .anySatisfy(message -> assertThat(message).contains(eventString));

  }
}
