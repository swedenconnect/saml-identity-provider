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
package se.swedenconnect.spring.saml.idp.autoconfigure.redis;

import org.redisson.Redisson;
import org.redisson.spring.starter.RedissonAutoConfigurationV2;
import org.redisson.spring.starter.RedissonProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.redis.core.RedisOperations;

/**
 * Activates Redisson if Redis is configured and Redisson is in classpath.
 *
 * @author Martin Lindström
 */
@AutoConfiguration
@AutoConfigureBefore(RedisAutoConfiguration.class)
@ConditionalOnProperty(prefix = "spring.data.redis", name = "host")
@ConditionalOnClass({ Redisson.class, RedisOperations.class, RedissonAutoConfigurationV2.class })
@EnableConfigurationProperties({ RedissonProperties.class, RedisProperties.class })
public class RedissonActivationAutoConfiguration extends RedissonAutoConfigurationV2 {
}
