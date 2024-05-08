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

import org.redisson.api.RedissonClient;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import se.swedenconnect.spring.saml.idp.audit.repository.RedissonTimeSeriesAuditEventRepository;

/**
 * Autoconfiguration for auditing support where a Redis {@link AuditEventRepository} is created.
 *
 * @author Martin Lindström
 */
@ConditionalOnProperty(value = "saml.idp.audit.redis.type", havingValue = "timeseries", matchIfMissing = false)
@ConditionalOnMissingBean(AuditEventRepository.class)
@ConditionalOnBean(RedissonClient.class)
@AutoConfiguration(before = AuditRepositoryAutoConfiguration.class)
public class RedissonAuditRepositoryAutoConfiguration {

  /**
   * Creates an {@link AuditEventRepositoryFactory} that creates a {@link RedissonTimeSeriesAuditEventRepository} bean.
   *
   * @param redissonClient the Redisson client bean
   * @return an {@link AuditEventRepositoryFactory}
   */
  @Bean
  AuditEventRepositoryFactory redisTimeseriesRepository(final RedissonClient redissonClient) {
    return (name, mapper, filter) -> new RedissonTimeSeriesAuditEventRepository(redissonClient, name, mapper, filter);
  }

}
