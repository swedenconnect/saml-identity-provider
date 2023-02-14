/*
 * Copyright 2023 Sweden Connect
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

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * Settings for the IdP metadata.
 * 
 * @author Martin Lindström
 */
public class MetadataSettings extends AbstractSettings {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param settings the settings
   */
  protected MetadataSettings(final Map<String, Object> settings) {
    super(settings);
  }

  /**
   * A template for the IdP metadata. A {@link Resource}.
   */
  public static final String SAML_METADATA_TEMPLATE = "template";

  /**
   * Gets the template for the IdP metadata.
   * 
   * @return the template or {@code null} if not assigned.
   */
  public Resource getTemplate() {
    return this.getSetting(SAML_METADATA_TEMPLATE);
  }

  /**
   * Tells how long the published IdP metadata can remain in a cache. A {@link Duration}.
   */
  public static final String SAML_METADATA_CACHE_DURATION = "cache-duration";

  /**
   * Tells how long the published IdP metadata can remain in a cache.
   * 
   * @return a {@link Duration}
   */
  public Duration getCacheDuration() {
    return this.getSetting(SAML_METADATA_CACHE_DURATION);
  }

  /**
   * Tells for how long a published metadata entry should be valid. A {@link Duration}.
   */
  public static final String SAML_METADATA_VALIDITY = "validity-period";

  /**
   * Tells for how long a published metadata entry should be valid.
   * 
   * @return a {@link Duration}
   */
  public Duration getValidityPeriod() {
    return this.getSetting(SAML_METADATA_VALIDITY);
  }

  /**
   * The declared entity categories, see <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
   * Categories for the Swedish eID Framework</a>. A {@link List} of {@link String}s.
   */
  public static final String SAML_METADATA_ENTITY_CATEGORIES = "entity-categories";

  /**
   * Gets the declared entity categories, see <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
   * Categories for the Swedish eID Framework</a>.
   * 
   * @return the entity category URI:s (may be an empty list)
   */
  public List<String> getEntityCategories() {
    return this.getSetting(SAML_METADATA_ENTITY_CATEGORIES);
  }

  /**
   * Constructs a new {@link Builder} with no settings.
   *
   * @return the {@link Builder}
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Constructs a new {@link Builder} with the provided settings.
   *
   * @param settings the settings to initialize the builder
   * @return the builder
   */
  public static Builder withSettings(final Map<String, Object> settings) {
    Assert.notEmpty(settings, "settings cannot be empty");
    return new Builder().settings(s -> s.putAll(settings));
  }

  /**
   * A builder for {@link MetadataSettings}.
   */
  public final static class Builder extends AbstractBuilder<MetadataSettings, Builder> {

    private Builder() {
    }

    /**
     * Assigns the template for the IdP metadata.
     * 
     * @param template the metadata template
     * @return the builder
     */
    public Builder template(final Resource template) {
      return this.setting(SAML_METADATA_TEMPLATE, template);
    }

    /**
     * Assigns how long the published IdP metadata can remain in a cache.
     * 
     * @param cacheDuration the cache duration
     * @return the builder
     */
    public Builder cacheDuration(final Duration cacheDuration) {
      return this.setting(SAML_METADATA_CACHE_DURATION, cacheDuration);
    }

    /**
     * Assigns for how long a published metadata entry should be valid.
     * 
     * @param validityPeriod for how long a published metadata entry should be valid
     * @return the builder
     */
    public Builder validityPeriod(final Duration validityPeriod) {
      return this.setting(SAML_METADATA_VALIDITY, validityPeriod);
    }
    
    /**
     * Assigns the declared entity categories, see <a href=
     * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
     * Categories for the Swedish eID Framework</a>.
     * 
     * @param entityCategories the entity category URI:s
     * @return the builder
     */
    public Builder entityCategories(final List<String> entityCategories) {
      return this.setting(SAML_METADATA_ENTITY_CATEGORIES, entityCategories);
    }    

    /** {@inheritDoc} */
    @Override
    protected void applyDefaultSettings() {
      if (this.getSettings().get(SAML_METADATA_CACHE_DURATION) == null) {
        this.cacheDuration(Duration.ofHours(24));
      }
      if (this.getSettings().get(SAML_METADATA_VALIDITY) == null) {
        this.validityPeriod(Duration.ofDays(7));
      }
      if (this.getSettings().get(SAML_METADATA_ENTITY_CATEGORIES) == null) {
        this.entityCategories(Collections.emptyList());
      }
    }

    /** {@inheritDoc} */
    @Override
    protected MetadataSettings buildObject() {
      return new MetadataSettings(this.getSettings());
    }

  }

}
