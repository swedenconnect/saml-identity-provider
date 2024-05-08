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
package se.swedenconnect.spring.saml.idp.autoconfigure.redis;

import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;

import lombok.Getter;
import lombok.Setter;

/**
 * Class for containing additional Redis cluster properties.
 * <p>
 * Note: Has only effect if Redisson is being used as Redis client.
 * </p>
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@ConfigurationProperties(prefix = "spring.data.redis.cluster-ext")
public class RedissonClusterProperties implements InitializingBean {

  /**
   * A list of NAT translation entries.
   */
  @Getter
  @Setter
  private List<NatTranslationEntry> natTranslation;

  /**
   * Node type used for read operation. The default value is MASTER. Available values: SLAVE - Read from slave nodes,
   * uses MASTER if no SLAVES are available, MASTER - Read from master node, MASTER_SLAVE - Read from master and slave
   * nodes.
   */
  @Getter
  @Setter
  private String readMode = "MASTER";

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws IllegalArgumentException {
    if (this.natTranslation != null) {
      for (final NatTranslationEntry entry : this.natTranslation) {
        Assert.hasText(entry.getTo(), "Invalid NAT translation configuration - 'to' is required");
        Assert.hasText(entry.getFrom(), "Invalid NAT translation configuration - 'from' is required");
      }
    }
    if (this.readMode == null) {
      this.readMode = "MASTER";
    }
    try {
      ReadMode.valueOf(this.readMode);
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Invalid value for read-mode");
    }
  }

  /**
   * An entry for NAT translation.
   */
  public static class NatTranslationEntry {

    /**
     * Address to translate from.
     */
    @Getter
    @Setter
    private String from;

    /**
     * Address to translate to.
     */
    @Getter
    @Setter
    private String to;
  }

  /**
   * Read mode from Redis cluster.
   */
  public enum ReadMode {

    /**
     * Read from slave nodes.
     */
    SLAVE,

    /**
     * Read from master node.
     */
    MASTER,

    /**
     * Read from master and slave nodes.
     */
    MASTER_SLAVE,
  }

}
