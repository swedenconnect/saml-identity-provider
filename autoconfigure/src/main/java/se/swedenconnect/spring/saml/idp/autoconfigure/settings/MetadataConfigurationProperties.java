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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;
import org.springframework.core.io.Resource;

import lombok.Data;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.ContactPersonType;

/**
 * Configuration properties for IdP metadata.
 *
 * @author Martin Lindström
 */
public class MetadataConfigurationProperties {

  /**
   * A template for the IdP metadata.
   */
  @Setter
  @Getter
  private Resource template;

  /**
   * Tells how long the published IdP metadata can remain in a cache.
   */
  @Setter
  @Getter
  private Duration cacheDuration;

  /**
   * Tells for how long a published metadata entry should be valid.
   */
  @Setter
  @Getter
  private Duration validityPeriod;

  /**
   * The {@code alg:DigestMethod} elements to include in the metadata.
   */
  @Setter
  @Getter
  private List<String> digestMethods;

  /**
   * Whether {@code alg:DigestMethod} elements should be placed in an {@code Extensions} element under the role
   * descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:DigestMethod} elements are
   * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}.
   */
  @Setter
  @Getter
  private boolean includeDigestMethodsUnderRole;

  /**
   * The {@code alg:SigningMethod} elements to include in the metadata.
   */
  @Setter
  @Getter
  private List<SigningMethod> signingMethods;

  /**
   * Whether {@code alg:SigningMethod} elements should be placed in an {@code Extensions} element under the role
   * descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:SigningMethod} elements are
   * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}.
   */
  @Setter
  @Getter
  private boolean includeSigningMethodsUnderRole;

  /**
   * The {@code md:EncryptionMethod} elements that should be included under the {@code md:KeyDescriptor} for
   * the encryption key. Note that these algorithms must match the configured encryption key.
   */
  @Setter
  @Getter
  private List<EncryptionMethod> encryptionMethods;

  /**
   * The metadata {@code UIInfo} element.
   */
  @Setter
  @Getter
  private UIInfo uiInfo;

  /**
   * Attribute names that should be included under the {@code RequestedPrincipalSelection} metadata extension.
   */
  @Setter
  @Getter
  private List<String> requestedPrincipalSelection;

  /**
   * The metadata {@code Organization} element.
   */
  @Setter
  @Getter
  private Organization organization;

  /**
   * The metadata {@code ContactPerson} elements.
   */
  @Setter
  @Getter
  private Map<ContactPersonType, ContactPerson> contactPersons;

  /**
   * Settings for {@code alg:SigningMethod} elements.
   *
   * @author Martin Lindström
   */
  public static class SigningMethod {

    /**
     * Identifies the algorithm by means of the URL defined for its use with the XML Signature specification.
     */
    @Setter
    @Getter
    private String algorithm;

    /**
     * The smallest key size, in bits, that the entity supports in conjunction with the algorithm. If omitted, no
     * minimum is implied.
     */
    @Setter
    @Getter
    private Integer minKeySize;

    /**
     * The largest key size, in bits, that the entity supports in conjunction with the algorithm. If omitted, no maximum
     * is implied.
     */
    @Setter
    @Getter
    private Integer maxKeySize;
  }

  /**
   * Settings for {@code md:EncryptionMethod} elements.
   *
   * @author Martin Lindström
   */
  public static class EncryptionMethod {

    /**
     * The algorithm URI of the encryption method.
     */
    @Setter
    @Getter
    private String algorithm;

    /**
     * The key size.
     */
    @Setter
    @Getter
    private Integer keySize;

    /**
     * The OAEP parameters (in Base64-encoding).
     */
    @Setter
    @Getter
    private String oaepParams;

    /**
     * If {@code algorithm} indicates a key transport algorithm where the digest algorithm needs to be given,
     * this field should be set to this algorithm URI.
     */
    @Setter
    @Getter
    private String digestMethod;

  }

  /**
   * Settings for the metadata {@code UIInfo} element.
   */
  public static class UIInfo {

    /**
     * UIInfo display names. The map key is the language tag and value is display name for that language.
     */
    @Setter
    @Getter
    private Map<String, String> displayNames;

    /**
     * UIInfo descriptions. The map key is the language tag and value is description for that language.
     */
    @Setter
    @Getter
    private Map<String, String> descriptions;

    /**
     * UIInfo logotypes.
     */
    @Setter
    @Getter
    private List<Logo> logotypes;

    /**
     * Representation of a {@code Logo} element.
     */
    public static class Logo {

      /**
       * Logotype URL. Mutually exclusive with path.
       */
      @Setter
      @Getter
      private String url;

      /**
       * Logotype path. Mutually exclusive with url.
       */
      @Setter
      @Getter
      private String path;

      /**
       * Logotype height in pixels.
       */
      @Setter
      @Getter
      private Integer height;

      /**
       * Logotype width in pixels.
       */
      @Setter
      @Getter
      private Integer width;

      /**
       * Logotype language tag.
       */
      @Setter
      @Getter
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
