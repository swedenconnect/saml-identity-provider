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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.actuate.autoconfigure.audit.AuditAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import com.fasterxml.jackson.databind.ObjectMapper;

import se.swedenconnect.spring.saml.idp.audit.repository.AuditEventMapper;
import se.swedenconnect.spring.saml.idp.audit.repository.DelegatingAuditEventRepository;
import se.swedenconnect.spring.saml.idp.audit.repository.FileBasedAuditEventRepository;
import se.swedenconnect.spring.saml.idp.audit.repository.FilteringAuditEventRepository;
import se.swedenconnect.spring.saml.idp.audit.repository.JsonAuditEventMapper;
import se.swedenconnect.spring.saml.idp.audit.repository.MemoryBasedAuditEventRepository;

/**
 * Auto configuration for auditing support where an {@link AuditEventRepository} is created.
 *
 * @author Martin Lindström
 */
@ConditionalOnMissingBean(AuditEventRepository.class)
@AutoConfiguration(before = AuditAutoConfiguration.class)
@EnableConfigurationProperties(AuditRepositoryConfigurationProperties.class)
public class AuditRepositoryAutoConfiguration {

  /** The audit properties. */
  private final AuditRepositoryConfigurationProperties properties;

  /** The JSON object mapper needed. */
  private final ObjectMapper objectMapper;

  /**
   * Constructor.
   *
   * @param properties the audit properties
   * @param objectMapper the JSON object mapper
   */
  public AuditRepositoryAutoConfiguration(final AuditRepositoryConfigurationProperties properties, final ObjectMapper objectMapper) {
    this.properties = Objects.requireNonNull(properties, "properties must not be null");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
  }

  /**
   * Creates an {@link AuditEventMapper} bean.
   *
   * @return the {@link AuditEventMapper} bean
   */
  @ConditionalOnMissingBean
  @Bean
  AuditEventMapper auditEventMapper() {
    return new JsonAuditEventMapper(this.objectMapper);
  }

  /**
   * Sets up an {@link AuditEventRepository} bean according to the configuration properties (unless such a bean has
   * already been provided).
   *
   * @param auditEventMapper the event mapper
   * @param redisFactory optional factory bean for creating Redis repositories
   * @return an {@link AuditEventRepository} bean
   * @throws IOException for errors setting up the file repository
   */
  @Bean
  AuditEventRepository auditEventRepository(final AuditEventMapper auditEventMapper,
      @Autowired(required = false) final AuditEventRepositoryFactory redisFactory) throws IOException {

    final List<AuditEventRepository> repositories = new ArrayList<>();
    final Predicate<AuditEvent> filter = FilteringAuditEventRepository.inclusionExclusionPredicate(
        this.properties.getIncludeEvents(), this.properties.getExcludeEvents());

    if (this.properties.getFile() != null) {
      repositories
          .add(new FileBasedAuditEventRepository(this.properties.getFile().getLogFile(), auditEventMapper, filter));
    }
    if (redisFactory != null) {
      repositories.add(redisFactory.create(this.properties.getRedis().getName(), auditEventMapper, filter));
    }
    if (this.properties.getInMemory() != null) {
      repositories.add(new MemoryBasedAuditEventRepository(filter, this.properties.getInMemory().getCapacity()));
    }

    // The file repository does not support reads, so if this is the only repository, install an in-memory
    // repository as well.
    //
    if (repositories.size() == 1 && this.properties.getFile() != null) {
      repositories.add(0, new MemoryBasedAuditEventRepository(filter));
    }

    // Make sure we have at least one repository ...
    //
    if (repositories.isEmpty()) {
      repositories.add(new MemoryBasedAuditEventRepository(filter));
    }

    return repositories.size() == 1 ? repositories.get(0) : new DelegatingAuditEventRepository(repositories);
  }

  /**
   * Throws a {@link BeanCreationException} when the type is "timeseries" and Redisson is not available.
   *
   * @return never returns anything
   * @throws BeanCreationException to signal that Redisson is required
   */
  @ConditionalOnProperty(value = "saml.idp.audit.redis.type", havingValue = "timeseries", matchIfMissing = false)
  @ConditionalOnMissingBean(type = "org.redisson.api.RedissonClient")
  @Bean
  AuditEventRepositoryFactory noRedisTimeseriesRepository() {
    throw new BeanCreationException("saml.idp.audit.redis.type is set to 'timeseries', but Redisson is not available");
  }

  /**
   * Throws a {@link BeanCreationException} when the type is "list" and Redis is not available.
   *
   * @return never returns anything
   * @throws BeanCreationException to signal that Redis is required
   */
  @ConditionalOnProperty(value = "saml.idp.audit.redis.type", havingValue = "list", matchIfMissing = false)
  @ConditionalOnMissingBean(type = "org.springframework.data.redis.core.StringRedisTemplate")
  @Bean
  AuditEventRepositoryFactory noRedisListRepository() {
    throw new BeanCreationException("saml.idp.audit.redis.type is set to 'list', but Redis is not available");
  }

}
