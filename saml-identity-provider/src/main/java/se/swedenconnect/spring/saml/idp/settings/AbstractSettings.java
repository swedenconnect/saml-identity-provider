/*
 * Copyright 2022 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.settings;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Base implementation for configuration settings.
 *
 * @author Martin Lindström
 */
public abstract class AbstractSettings implements Serializable {

  /** For serializing. */
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The settings. */
  private final Map<String, Object> settings;

  /**
   * Constructor.
   *
   * @param settings the settings
   */
  protected AbstractSettings(final Map<String, Object> settings) {
    this.settings = Collections.unmodifiableMap(new HashMap<>(settings));
  }

  /**
   * Gets a named configuration setting.
   *
   * @param name the name of the setting
   * @param <T> the type of the setting
   * @return the setting value, or null if not available
   */
  @SuppressWarnings("unchecked")
  public <T> T getSetting(final String name) {
    Assert.hasText(name, "name cannot be empty");
    return (T) this.getSettings().get(name);
  }

  /**
   * Returns a {@code Map} of the configuration settings.
   *
   * @return a map
   */
  public Map<String, Object> getSettings() {
    return this.settings;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || this.getClass() != obj.getClass()) {
      return false;
    }
    final AbstractSettings that = (AbstractSettings) obj;
    return this.settings.equals(that.settings);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.settings);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s", this.settings);
  }

  /**
   * A builder for subclasses of {@link AbstractSettings}.
   */
  protected static abstract class AbstractBuilder<T extends AbstractSettings, B extends AbstractBuilder<T, B>> {
    private final Map<String, Object> settings = new HashMap<>();

    /**
     * Constructor.
     */
    protected AbstractBuilder() {
    }

    /**
     * Assigns a configuration setting.
     *
     * @param name the setting name
     * @param value the setting value
     * @return the builder
     */
    public B setting(final String name, final Object value) {
      Assert.hasText(name, "name cannot be empty");
      if (value == null) {
        return this.getThis();
      }
      this.getSettings().put(name, value);
      return this.getThis();
    }

    /**
     * A {@code Consumer} of the configuration settings {@code Map} allowing the ability to add, replace, or remove.
     *
     * @param settingsConsumer a Consumer of the configuration settings Map
     * @return the builder
     */
    public B settings(final Consumer<Map<String, Object>> settingsConsumer) {
      settingsConsumer.accept(this.getSettings());
      return this.getThis();
    }

    /**
     * Builds the settings object and applies default values to those settings that are mandatory and has not been
     * assigned.
     *
     * @return the settings object
     */
    public final T build() {
      this.applyDefaultSettings();
      return this.buildObject();
    }

    /**
     * Is invoked by {@link #build()} to apply default values to those settings that are mandatory and has not been
     * assigned.
     */
    protected abstract void applyDefaultSettings();

    /**
     * Is invoked by {@link #build()} and builds the settings object.
     * 
     * @return the settings object
     */
    protected abstract T buildObject();

    /**
     * Gets the settings as a map.
     *
     * @return a map of the settings
     */
    protected final Map<String, Object> getSettings() {
      return this.settings;
    }

    /**
     * Gets the builder.
     *
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    protected final B getThis() {
      return (B) this;
    }

  }

}
