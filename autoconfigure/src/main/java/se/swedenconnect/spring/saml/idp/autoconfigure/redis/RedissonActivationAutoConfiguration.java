/*
 * Copyright 2023-2026 Sweden Connect
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
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.data.redis.autoconfigure.DataRedisProperties;
import org.springframework.context.annotation.Conditional;
import org.springframework.data.redis.core.RedisOperations;

/**
 * Activates Redisson if Redis is configured and Redisson is in classpath.
 *
 * @author Martin Lindström
 */
@AutoConfiguration
@AutoConfigureBefore(DataRedisAutoConfiguration.class)
//@ConditionalOnProperty(prefix = "spring.data.redis", name = "host")
@Conditional(RedissonCondition.class)
@ConditionalOnClass({ Redisson.class, RedisOperations.class, RedissonAutoConfigurationV2.class })
@EnableConfigurationProperties({ RedissonProperties.class, DataRedisProperties.class })
public class RedissonActivationAutoConfiguration extends RedissonAutoConfigurationV2 {
}
