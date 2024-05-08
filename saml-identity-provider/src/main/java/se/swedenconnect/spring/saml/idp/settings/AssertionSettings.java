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
package se.swedenconnect.spring.saml.idp.settings;

import java.io.Serial;
import java.time.Duration;
import java.util.Map;

import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Settings that controls how SAML Assertions are issued.
 * 
 * @author Martin Lindström
 */
public class AssertionSettings extends AbstractSettings {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;
  
  /**
   * Default value for the {@link #NOT_ON_OR_AFTER_DURATION} setting.
   */
  public static final Duration NOT_ON_OR_AFTER_DURATION_DEFAULT = Duration.ofMinutes(5);
  
  /**
   * Default value for the {@link #NOT_BEFORE_DURATION} setting.
   */
  public static final Duration NOT_BEFORE_DURATION_DEFAULT = Duration.ofSeconds(10);
  
  /**
   * Default value for the {@link #ENCRYPT_ASSERTIONS} setting.
   */
  public static final Boolean ENCRYPT_ASSERTIONS_DEFAULT = Boolean.TRUE;

  /**
   * Constructor.
   *
   * @param settings the settings
   */
  protected AssertionSettings(final Map<String, Object> settings) {
    super(settings);
  }

  /**
   * Tells whether the Identity Provider encrypts assertions. A {@link Boolean}.
   */
  public static final String ENCRYPT_ASSERTIONS = "encrypt-assertions";

  /**
   * Tells whether the Identity Provider encrypts assertions.
   * 
   * @return {@code true} if assertions should be encrypted and {@code false} otherwise.
   */
  public Boolean getEncryptAssertions() {
    return this.getSetting(ENCRYPT_ASSERTIONS);
  }

  /**
   * A setting that tells the time restrictions the IdP puts on an Assertion concerning "not on or after". A
   * {@link Duration}.
   */
  public static final String NOT_ON_OR_AFTER_DURATION = "not-after";

  /**
   * Gets the {@link Duration} that tells the time restrictions the IdP puts on an Assertion concerning "not on or
   * after".
   * 
   * @return a {@link Duration}
   */
  public Duration getNotOnOrAfterDuration() {
    return this.getSetting(NOT_ON_OR_AFTER_DURATION);
  }
  
  /**
   * A setting that tells the time restrictions the IdP puts on an Assertion concerning "not before". A
   * {@link Duration}.
   */
  public static final String NOT_BEFORE_DURATION = "not-before";

  /**
   * Gets the {@link Duration} that tells the time restrictions the IdP puts on an Assertion concerning "not before".
   * 
   * @return a {@link Duration}
   */
  public Duration getNotBeforeDuration() {
    return this.getSetting(NOT_BEFORE_DURATION);
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
   * A builder for {@link AssertionSettings}.
   */
  public final static class Builder extends AbstractBuilder<AssertionSettings, Builder> {

    private Builder() {
    }

    /**
     * Assigns the {@link Duration} that tells the time restrictions the IdP puts on an Assertion concerning "not on or
     * after".
     * 
     * @param notOnOrAfter a {@link Duration}
     * @return the builder
     */
    public Builder notOnOrAfterDuration(final Duration notOnOrAfter) {
      return this.setting(NOT_ON_OR_AFTER_DURATION, notOnOrAfter);
    }
    
    /**
     * Assigns the {@link Duration} that tells the time restrictions the IdP puts on an Assertion concerning "not before".
     * 
     * @param notBefore a {@link Duration}
     * @return the builder
     */
    public Builder notBeforeDuration(final Duration notBefore) {
      return this.setting(NOT_BEFORE_DURATION, notBefore);
    }    

    /**
     * Assigns whether the Identity Provider encrypts assertions.
     * 
     * @param encryptAssertions {@code true} if assertions should be encrypted and {@code false} otherwise
     * @return the builder
     */
    public Builder encryptAssertions(final Boolean encryptAssertions) {
      return this.setting(ENCRYPT_ASSERTIONS, encryptAssertions);
    }

    /** {@inheritDoc} */
    @Override
    protected void applyDefaultSettings() {
      if (this.getSettings().get(NOT_ON_OR_AFTER_DURATION) == null) {
        this.notOnOrAfterDuration(NOT_ON_OR_AFTER_DURATION_DEFAULT);
      }
      if (this.getSettings().get(NOT_BEFORE_DURATION) == null) {
        this.notBeforeDuration(NOT_BEFORE_DURATION_DEFAULT);
      }
      if (this.getSettings().get(ENCRYPT_ASSERTIONS) == null) {
        this.encryptAssertions(ENCRYPT_ASSERTIONS_DEFAULT);
      }
    }

    /** {@inheritDoc} */
    @Override
    protected AssertionSettings buildObject() {
      return new AssertionSettings(this.getSettings());
    }
  }

}
