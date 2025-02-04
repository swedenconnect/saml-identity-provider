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

import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.OnPropertyListCondition;
import org.springframework.context.annotation.Conditional;

/**
 * Condition class for checking whether to enable Redisson.
 *
 * @author Martin Lindström
 */
public class RedissonCondition extends AnyNestedCondition {

  /**
   * Default constructor.
   */
  public RedissonCondition() {
    super(ConfigurationPhase.PARSE_CONFIGURATION);
  }

  @ConditionalOnProperty(prefix = "spring.data.redis", name = "host")
  static class RedisHostCondition {
  }

  @ConditionalOnProperty(prefix = "spring.data.redis", name = "url")
  static class RedisUrlCondition {
  }

  @Conditional(OnRedisClusterCondition.class)
  static class RedisClusterCondition {
  }

  static class OnRedisClusterCondition extends OnPropertyListCondition {

    public OnRedisClusterCondition() {
      super("spring.data.redis.cluster.nodes",
          () -> ConditionMessage.forCondition("spring.data.redis.cluster.nodes"));
    }
  }

}
