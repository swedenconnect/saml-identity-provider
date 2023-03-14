/*
 * Copyright 2022-2023 Sweden Connect
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

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.springframework.core.io.Resource;

import lombok.Data;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.ContactPersonType;

/**
 * Configuration properties for IdP metadata.
 * 
 * @author Martin Lindström
 */
@Data
public class MetadataConfigurationProperties {

  /**
   * A template for the IdP metadata.
   */
  private Resource template;

  /**
   * Tells how long the published IdP metadata can remain in a cache.
   */
  private Duration cacheDuration;

  /**
   * Tells for how long a published metadata entry should be valid.
   */
  private Duration validityPeriod;

  /**
   * The metadata {@code UIInfo} element.
   */
  private UIInfo uiInfo;

  /**
   * The metadata {@code Organization} element.
   */
  private Organization organization;

  /**
   * The metadata {@code ContactPerson} elements.
   */
  private Map<ContactPersonType, ContactPerson> contactPersons;

  /**
   * Settings for the metadata {@code UIInfo} element.
   */
  @Data
  public static class UIInfo {

    /**
     * UIInfo display names. The map key is the language tag and value is display name for that language.
     */
    private Map<String, String> displayNames;

    /**
     * UIInfo descriptions. The map key is the language tag and value is description for that language.
     */
    private Map<String, String> descriptions;

    /**
     * UIInfo logotypes.
     */
    private List<Logo> logotypes;

    /**
     * Representation of a {@code Logo} element.
     */
    @Data
    public static class Logo {

      /**
       * Logotype URL. Mutually exclusive with path.
       */
      private String url;

      /**
       * Logotype path. Mutually exclusive with url.
       */
      private String path;

      /**
       * Logotype height in pixels.
       */
      private Integer height;

      /**
       * Logotype width in pixels.
       */
      private Integer width;

      /**
       * Logotype language tag.
       */
      private String languageTag;
    }
  }

  /**
   * Settings for the {@code Organization} metadata element.
   */
  @Data
  public static class Organization {

    /**
     * The {@code OrganizationName}. The map key is the language tag and value is display name for that language.
     */
    private Map<String, String> names;

    /**
     * The {@code OrganizationDisplayName}. The map key is the language tag and value is display name for that language.
     */
    private Map<String, String> displayNames;

    /**
     * The {@code OrganizationURL}. The map key is the language tag and value is display name for that language.
     */
    private Map<String, String> urls;
  }

  /**
   * Settings for the {@code ContactPerson} metadata element.
   */
  @Data
  public static class ContactPerson {

    /**
     * The {@code Company} element.
     */
    private String company;

    /**
     * The {@code GivenName} element.
     */
    private String givenName;

    /**
     * The {@code SurName} element.
     */
    private String surname;

    /**
     * The {@code EmailAddress} elements.
     */
    private List<String> emailAddresses;

    /**
     * The {@code TelephoneNumber} elements.
     */
    private List<String> telephoneNumbers;
  }

}
