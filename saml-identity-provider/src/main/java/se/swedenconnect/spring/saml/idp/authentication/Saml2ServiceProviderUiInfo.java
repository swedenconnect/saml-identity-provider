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
package se.swedenconnect.spring.saml.idp.authentication;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * A utility class that holds information about a SAML Service Provider that the IdP may want to use in its UI.
 * <p>
 * Regarding the display names: The class first looks for display names under the {@code mdui:UIInfo} metadata
 * extension, then under {@code Organization/OrganizationDisplayNames} and finally under
 * {@code Organization/OrganizationNames}.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2ServiceProviderUiInfo implements Serializable {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** Constant used if no language tag has been set in SP metadata. */
  public static final String NO_LANG = "nolang";

  /** The SP entityID. */
  private final String entityId;

  /** A map of the display names, where the map key is the language tag and the value is the display name. */
  private final Map<String, String> displayNames;

  /** A map of the descriptions, where the map key is the language tag and the value is the description. */
  private final Map<String, String> descriptions;

  /** The logotypes. */
  private final List<Logotype> logotypes;

  /**
   * Constructor.
   *
   * @param metadata the SAML metadata for the SP
   */
  public Saml2ServiceProviderUiInfo(final EntityDescriptor metadata) {
    Assert.notNull(metadata, "metadata must not be null");
    this.entityId = metadata.getEntityID();

    final UIInfo uiInfo = Optional.ofNullable(metadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS))
        .map(SPSSODescriptor::getExtensions)
        .map(e -> e.getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME))
        .filter(l -> !l.isEmpty())
        .map(l -> l.get(0))
        .map(UIInfo.class::cast)
        .orElse(null);

    final Map<String, String> displayNamesMap = new HashMap<>();

    if (uiInfo != null) {
      uiInfo.getDisplayNames()
          .forEach(d -> displayNamesMap.put(Optional.ofNullable(d.getXMLLang()).orElse(NO_LANG), d.getValue()));
      this.descriptions = uiInfo.getDescriptions().stream()
          .collect(Collectors.toUnmodifiableMap(
              d -> Optional.ofNullable(d.getXMLLang()).orElse(NO_LANG), XSString::getValue));
      this.logotypes = uiInfo.getLogos().stream()
          .map(Logotype::new)
          .filter(Logotype::isValid)
          .toList();
    }
    else {
      this.descriptions = Collections.emptyMap();
      this.logotypes = Collections.emptyList();
    }

    if (metadata.getOrganization() != null) {
      metadata.getOrganization().getDisplayNames()
          .forEach(dn -> {
            final String lang = Optional.ofNullable(dn.getXMLLang()).orElse(NO_LANG);
            if (!displayNamesMap.containsKey(lang)) {
              displayNamesMap.put(lang, dn.getValue());
            }
          });
      metadata.getOrganization().getOrganizationNames()
          .forEach(on -> {
            final String lang = Optional.ofNullable(on.getXMLLang()).orElse(NO_LANG);
            if (!displayNamesMap.containsKey(lang)) {
              displayNamesMap.put(lang, on.getValue());
            }
          });
    }

    this.displayNames = Collections.unmodifiableMap(displayNamesMap);
  }

  /**
   * Gets the entityID for the SP.
   *
   * @return the SP entityID
   */
  public String getEntityId() {
    return this.entityId;
  }

  /**
   * Gets a map of the display names, where the map key is the language tag and the value is the display name.
   *
   * @return the display names
   */
  public Map<String, String> getDisplayNames() {
    return this.displayNames;
  }

  /**
   * Gets the display name for the given language. If no mapping exists for the language and there is a display name
   * with no language tag available, this is returned.
   *
   * @param languageTag the language tag
   * @return the display name or {@code null}
   */
  public String getDisplayName(final String languageTag) {
    return this.displayNames.getOrDefault(languageTag, this.displayNames.get(NO_LANG));
  }

  /**
   * Gets a map of the descriptions, where the map key is the language tag and the value is the description.
   *
   * @return the descriptions
   */
  public Map<String, String> getDescriptions() {
    return this.descriptions;
  }

  /**
   * Gets the description for the given language. If no mapping exists for the language and there is a description with
   * no language tag available, this is returned.
   *
   * @param languageTag the language tag
   * @return the description or {@code null}
   */
  public String getDescription(final String languageTag) {
    return this.descriptions.getOrDefault(languageTag, this.descriptions.get(NO_LANG));
  }

  /**
   * Gets the logotypes.
   *
   * @return a list of logotypes
   */
  public List<Logotype> getLogotypes() {
    return this.logotypes;
  }

  /**
   * Returns the first logotype for which the supplied {@link Predicate} evaluates to {@code true}.
   *
   * @param predicate the predicate for testing the possible logotypes
   * @return a matching logotype, or else {@code null}
   */
  public Logotype getLogotype(final Predicate<Logotype> predicate) {
    Assert.notNull(predicate, "predicate must not be null");
    return this.logotypes.stream()
        .filter(predicate)
        .findFirst()
        .orElse(null);
  }

  /**
   * Representation of a logotype.
   */
  public static class Logotype {

    /** The logotype URL. */
    private final String url;

    /** The height (in pixels). */
    private final Integer height;

    /** The width (in pixels). */
    private final Integer width;

    /** The language tag. May be {@code null}. */
    private final String language;

    /**
     * Constructor.
     *
     * @param logo the OpenSAML {@link Logo}.
     */
    public Logotype(final Logo logo) {
      this.url = logo.getURI();
      this.height = logo.getHeight();
      this.width = logo.getWidth();
      this.language = logo.getXMLLang();
    }

    /**
     * Gets the logotype URL.
     *
     * @return the logotype URL
     */
    public String getUrl() {
      return this.url;
    }

    /**
     * Gets the height (in pixels)
     *
     * @return the height
     */
    public Integer getHeight() {
      return this.height;
    }

    /**
     * Gets the width (in pixels)
     *
     * @return the width
     */
    public Integer getWidth() {
      return this.width;
    }

    /**
     * Gets the language tag.
     *
     * @return the language tag or {@code null} if not set
     */
    public String getLanguage() {
      return this.language;
    }

    /**
     * Tells whether the object is usable (i.e., is the URL set?)
     *
     * @return {@code true} if the URL is set and {@code false} otherwise
     */
    public boolean isValid() {
      return this.url != null;
    }

  }

}
