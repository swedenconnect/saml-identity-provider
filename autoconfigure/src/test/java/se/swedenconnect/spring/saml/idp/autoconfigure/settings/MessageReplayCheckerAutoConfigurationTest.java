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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.storage.ReplayCache;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.replay.InMemoryReplayCache;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.replay.RedisReplayCache;

/**
 * Test cases for MessageReplayCheckerAutoConfiguration, in particular for which {@link ReplayCache} that is selected.
 *
 * @author Martin Lindström
 */
public class MessageReplayCheckerAutoConfigurationTest {

  /** The IdP entity ID is a required property. */
  private static final String ENTITY_ID_PROPERTY = "saml.idp.entity-id=https://idp.example.com";

  /** A context where Redis is on the classpath, but where no Redis template bean exists. */
  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
      .withPropertyValues(ENTITY_ID_PROPERTY)
      .withConfiguration(AutoConfigurations.of(MessageReplayCheckerAutoConfiguration.class));

  /** Captures what the autoconfiguration logs. */
  private ListAppender<ILoggingEvent> logAppender;

  @BeforeEach
  public void setupLogAppender() {
    this.logAppender = new ListAppender<>();
    this.logAppender.start();
    this.logger().addAppender(this.logAppender);
  }

  @AfterEach
  public void removeLogAppender() {
    this.logger().detachAppender(this.logAppender);
    this.logAppender.stop();
  }

  /**
   * Type not set and Redis available - the Redis cache is used.
   */
  @Test
  public void testTypeNotSetWithRedis() {
    this.withRedis().run(context -> {
      assertThat(context).hasSingleBean(ReplayCache.class);
      assertThat(context.getBean(ReplayCache.class)).isInstanceOf(RedisReplayCache.class);
      assertThat(context).hasSingleBean(MessageReplayChecker.class);
      this.assertLogged("saml.idp.replay.type is not set and Redis is available - using RedisReplayCache");
    });
  }

  /**
   * Type not set and no Redis template bean - the in-memory cache is used.
   */
  @Test
  public void testTypeNotSetWithoutRedisTemplate() {
    this.contextRunner.run(context -> {
      assertThat(context).hasSingleBean(ReplayCache.class);
      assertThat(context.getBean(ReplayCache.class)).isInstanceOf(InMemoryReplayCache.class);
      this.assertLogged("saml.idp.replay.type is not set and Redis is not available - using InMemoryReplayCache");
    });
  }

  /**
   * Type not set and Redis not on the classpath - the in-memory cache is used.
   */
  @Test
  public void testTypeNotSetWithoutRedisOnClasspath() {
    this.withoutRedisOnClasspath().run(context -> {
      assertThat(context).hasSingleBean(ReplayCache.class);
      assertThat(context.getBean(ReplayCache.class)).isInstanceOf(InMemoryReplayCache.class);
      this.assertLogged("saml.idp.replay.type is not set and Redis is not available - using InMemoryReplayCache");
    });
  }

  /**
   * Type is memory - the in-memory cache is used also when Redis is available.
   */
  @Test
  public void testTypeMemoryWithRedis() {
    this.withRedis().withPropertyValues("saml.idp.replay.type=memory").run(context -> {
      assertThat(context).hasSingleBean(ReplayCache.class);
      assertThat(context.getBean(ReplayCache.class)).isInstanceOf(InMemoryReplayCache.class);
      this.assertLogged("saml.idp.replay.type is 'memory' - using InMemoryReplayCache");
    });
  }

  /**
   * Type is memory and Redis is not available - the in-memory cache is used.
   */
  @Test
  public void testTypeMemoryWithoutRedis() {
    this.contextRunner.withPropertyValues("saml.idp.replay.type=memory").run(context -> {
      assertThat(context).hasSingleBean(ReplayCache.class);
      assertThat(context.getBean(ReplayCache.class)).isInstanceOf(InMemoryReplayCache.class);
    });
  }

  /**
   * Type is redis and Redis is available - the Redis cache is used.
   */
  @Test
  public void testTypeRedisWithRedis() {
    this.withRedis().withPropertyValues("saml.idp.replay.type=redis").run(context -> {
      assertThat(context).hasSingleBean(ReplayCache.class);
      assertThat(context.getBean(ReplayCache.class)).isInstanceOf(RedisReplayCache.class);
      this.assertLogged("saml.idp.replay.type is 'redis' - using RedisReplayCache");
    });
  }

  /**
   * The type values are not case sensitive, as before.
   */
  @Test
  public void testTypeIsNotCaseSensitive() {
    this.withRedis().withPropertyValues("saml.idp.replay.type=REDIS").run(context -> assertThat(
        context.getBean(ReplayCache.class)).isInstanceOf(RedisReplayCache.class));

    this.withRedis().withPropertyValues("saml.idp.replay.type=Memory").run(context -> assertThat(
        context.getBean(ReplayCache.class)).isInstanceOf(InMemoryReplayCache.class));
  }

  /**
   * Type is redis, but no Redis template bean exists - the application does not start.
   */
  @Test
  public void testTypeRedisWithoutRedisTemplate() {
    this.contextRunner.withPropertyValues("saml.idp.replay.type=redis").run(context -> {
      assertThat(context).hasFailed();
      assertThat(context.getStartupFailure()).rootCause()
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("saml.idp.replay.type is 'redis', but Redis is not available - a StringRedisTemplate bean "
              + "is required");
    });
  }

  /**
   * Type is redis, but Redis is not on the classpath - the application does not start.
   */
  @Test
  public void testTypeRedisWithoutRedisOnClasspath() {
    this.withoutRedisOnClasspath().withPropertyValues("saml.idp.replay.type=redis").run(context -> {
      assertThat(context).hasFailed();
      assertThat(context.getStartupFailure()).rootCause()
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("but Redis is not available");
    });
  }

  /**
   * An unknown type value - the application does not start.
   */
  @Test
  public void testUnknownType() {
    this.withRedis().withPropertyValues("saml.idp.replay.type=distributed").run(context -> {
      assertThat(context).hasFailed();
      assertThat(context.getStartupFailure()).rootCause()
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("Invalid value for saml.idp.replay.type: 'distributed' - expected 'memory' or 'redis'");
    });
  }

  /**
   * A {@link ReplayCache} bean supplied by the application is used, and no cache is autoconfigured.
   */
  @Test
  public void testApplicationSuppliedReplayCache() {
    final ReplayCache replayCache = Mockito.mock(ReplayCache.class);

    this.withRedis().withBean("applicationReplayCache", ReplayCache.class, () -> replayCache).run(context -> {
      assertThat(context).hasSingleBean(ReplayCache.class);
      assertThat(context.getBean(ReplayCache.class)).isSameAs(replayCache);
      assertThat(context).hasSingleBean(MessageReplayChecker.class);
    });
  }

  /**
   * A {@link MessageReplayChecker} bean supplied by the application turns the whole autoconfiguration off.
   */
  @Test
  public void testApplicationSuppliedMessageReplayChecker() {
    final MessageReplayChecker checker = Mockito.mock(MessageReplayChecker.class);

    this.withRedis().withBean("applicationChecker", MessageReplayChecker.class, () -> checker).run(context -> {
      assertThat(context).doesNotHaveBean(ReplayCache.class);
      assertThat(context.getBean(MessageReplayChecker.class)).isSameAs(checker);
    });
  }

  /**
   * Gets a runner where Redis is available, i.e. where Spring Boot's Redis autoconfiguration declares a
   * {@link StringRedisTemplate} bean.
   *
   * @return an {@link ApplicationContextRunner}
   */
  private ApplicationContextRunner withRedis() {
    return this.contextRunner.withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class));
  }

  /**
   * Gets a runner where Spring Data Redis is not on the classpath.
   *
   * @return an {@link ApplicationContextRunner}
   */
  private ApplicationContextRunner withoutRedisOnClasspath() {
    return this.contextRunner.withClassLoader(new FilteredClassLoader(StringRedisTemplate.class));
  }

  /**
   * Asserts that the given message was logged.
   *
   * @param message the expected message
   */
  private void assertLogged(final String message) {
    final List<String> messages = this.logAppender.list.stream()
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
    Assertions.assertTrue(messages.contains(message),
        "Expected '%s' to be logged, but was: %s".formatted(message, messages));
  }

  /**
   * Gets the logger of the autoconfiguration class.
   *
   * @return the logger
   */
  private Logger logger() {
    return (Logger) LoggerFactory.getLogger(MessageReplayCheckerAutoConfiguration.class);
  }

}
