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
package se.swedenconnect.spring.saml.idp.autoconfigure.session;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration;

import se.swedenconnect.spring.saml.idp.autoconfigure.redis.RedisExtensionsAutoConfiguration;
import se.swedenconnect.spring.saml.idp.autoconfigure.redis.RedissonExtensionsAutoConfiguration;

/**
 * For setting up Spring Session using Redis.
 *
 * @author Martin Lindström
 */
@ConditionalOnProperty(value = "saml.idp.session.module", havingValue = "redis", matchIfMissing = false)
@ConditionalOnClass(RedisHttpSessionConfiguration.class)
@ConditionalOnWebApplication
@AutoConfiguration(after = { RedissonExtensionsAutoConfiguration.class, RedisExtensionsAutoConfiguration.class })
@EnableRedisHttpSession
public class RedisSessionAutoConfiguration {
}
