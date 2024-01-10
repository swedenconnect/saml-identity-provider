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
package se.swedenconnect.spring.saml.idp.autoconfigure.audit;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.audit.repository.MemoryBasedAuditEventRepository;

/**
 * Configuration properties for auditing.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("saml.idp.audit")
@Slf4j
public class AuditRepositoryConfigurationProperties implements InitializingBean {

  /**
   * For audit logging to a file.
   */
  @Getter
  @Setter
  private FileRepository file;

  /**
   * For in-memory audit logging.
   */
  @Getter
  @Setter
  private InMemoryRepository inMemory;

  /**
   * For using Redis to store audit events. Note that a Redis client must also be configured in order for this setting
   * to be effective.
   */
  @Getter
  @Setter
  private RedisRepository redis;

  /**
   * A list of event ID:s for the events that will be logged to the repository. If not set, all events will
   * be logged (except to excluded by the "exclude-events").
   */
  @Getter
  private List<String> includeEvents = new ArrayList<>();

  /**
   * A list of event ID:s to exclude from being logged to the repository. See also the "include-events"
   * setting.
   */
  @Getter
  private List<String> excludeEvents = new ArrayList<>();

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.file != null) {
      this.file.afterPropertiesSet();
    }
    if (this.inMemory != null) {
      this.inMemory.afterPropertiesSet();
    }
    if (this.redis != null) {
      this.redis.afterPropertiesSet();
    }

    // We need at least one repository
    if (this.file == null && this.inMemory == null && this.redis == null) {
      this.inMemory = new InMemoryRepository();
      log.info("No repository was configured for saml.idp.audit - using inMemory");
    }
  }

  /**
   * For audit logging to a file.
   */
  public static class FileRepository implements InitializingBean {

    /**
     * The complete path to the log file where to write audit events.
     */
    @Getter
    @Setter
    private String logFile;

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() throws Exception {
      Assert.hasText(this.logFile, "saml.idp.audit.file.log-file must be assigned");
    }

  }

  /**
   * For in-memory audit logging.
   */
  public static class InMemoryRepository implements InitializingBean {

    /**
     * The number of events that the repository should hold.
     */
    @Getter
    @Setter
    private Integer capacity = MemoryBasedAuditEventRepository.DEFAULT_CAPACITY;

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() throws Exception {
      if (this.capacity == null) {
        this.capacity = MemoryBasedAuditEventRepository.DEFAULT_CAPACITY;
      }
    }

  }

  /**
   * For Redis storage of audit entries.
   */
  public static class RedisRepository implements InitializingBean {

    /**
     * The name of the Redis list/time series object that will hold the audit events.
     */
    @Getter
    @Setter
    private String name;

    /**
     * The type of Redis storage - "list" or "timeseries". Note that Redisson is required for Redis Timeseries.
     */
    @Getter
    @Setter
    private String type;

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() throws Exception {
      if (this.type == null) {
        this.type = "list";
        log.info("saml.idp.audit.redis.type not set, defaulting to {}", this.type);
      }
      else {
        if (this.type.equalsIgnoreCase("list")) {
          this.type = "list";
        }
        else if (this.type.equalsIgnoreCase("timeseries")) {
          this.type = "timeseries";
        }
        else {
          throw new IllegalArgumentException(
              "Invalid value for saml.idp.audit.redis.type - expected 'list' or 'timeseries'");
        }
      }
      if (!StringUtils.hasText(this.name)) {
        if ("list".equals(this.type)) {
          this.name = "audit:list";
        }
        else {
          this.name = "audit:ts";
        }
        log.info("saml.idp.audit.redis.name not set, defaulting to '{}'", this.name);
      }
    }

  }

}
