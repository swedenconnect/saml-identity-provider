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

import org.redisson.spring.starter.RedissonAutoConfigurationV2;
import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;

import java.util.Objects;

/**
 * Disables Redisson autoconfiguration.
 *
 * @author Martin Lindström
 */
public class RedissonFilter implements AutoConfigurationImportFilter {

  public static final String DISABLE = RedissonAutoConfigurationV2.class.getName();

  @Override
  public boolean[] match(final String[] autoConfigurationClasses,
      final AutoConfigurationMetadata autoConfigurationMetadata) {

    final boolean[] matches = new boolean[autoConfigurationClasses.length];
    for (int i = 0; i < autoConfigurationClasses.length; i++) {
      matches[i] = !Objects.equals(DISABLE, autoConfigurationClasses[i]);
    }

    return matches;
  }

}
