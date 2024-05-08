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
package se.swedenconnect.spring.saml.idp.attributes;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.attribute.AttributeTemplate;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryRegistry;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.ServiceEntityCategory;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.metadata.EntityCategoryHelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A {@link RequestedAttributeProcessor} that extracts the requested attributes from declared entity categories. See
 * <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
 * Categories for the Swedish eID Framework</a>.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class EntityCategoryRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** The entity categories that the IdP has declared (to support). */
  private final Collection<String> idpDeclaredEntityCategories;

  /**
   * The registry of all supported entity categories. Defaults to the categories defined in <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
   * Categories for the Swedish eID Framework</a>.
   */
  private EntityCategoryRegistry entityCategoryRegistry;

  /**
   * Constructor.
   * 
   * @param idpDeclaredEntityCategories the entity categories declared by this IdP
   */
  public EntityCategoryRequestedAttributeProcessor(final Collection<String> idpDeclaredEntityCategories) {
    this.idpDeclaredEntityCategories =
        Objects.requireNonNull(idpDeclaredEntityCategories, "idpDeclaredEntityCategories must not be null");
    this.entityCategoryRegistry = EntityCategoryHelper.getDefaultEntityCategoryRegistry();
  }

  /**
   * Assigns a custom {@link EntityCategoryRegistry}. Defaults to the categories defined in <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
   * Categories for the Swedish eID Framework</a>.
   * 
   * @param entityCategoryRegistry the {@link EntityCategoryRegistry}
   */
  public void setEntityCategoryRegistry(final EntityCategoryRegistry entityCategoryRegistry) {
    this.entityCategoryRegistry =
        Objects.requireNonNull(entityCategoryRegistry, "entityCategoryRegistry must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public Collection<RequestedAttribute> extractRequestedAttributes(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken) {

    final List<ServiceEntityCategory> serviceCategories =
        EntityDescriptorUtils.getEntityCategories(authnRequestToken.getPeerMetadata()).stream()
            .map(e -> this.entityCategoryRegistry.getEntityCategory(e))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .filter(ServiceEntityCategory.class::isInstance)
            .filter(c -> this.idpDeclaredEntityCategories.contains(c.getUri()))
            .map(ServiceEntityCategory.class::cast)
            .toList();

    if (serviceCategories.isEmpty()) {
      log.debug("No matching service entity categories found that could be used to determine attribute release [{}]",
          authnRequestToken.getLogString());
      return Collections.emptyList();
    }

    final List<RequestedAttribute> requestedAttributes = new ArrayList<>();

    if (serviceCategories.size() == 1) {
      // Easy, just return the attributes ...
      final ServiceEntityCategory sec = serviceCategories.get(0);
      if (sec.getAttributeSet() != null) {
        Arrays.stream(sec.getAttributeSet().getRequiredAttributes())
            .map(t -> new ImplicitRequestedAttribute(sec.getUri(), t.getName(), t.getFriendlyName(), true))
            .forEach(requestedAttributes::add);
        Arrays.stream(sec.getAttributeSet().getRecommendedAttributes())
            .map(t -> new ImplicitRequestedAttribute(sec.getUri(), t.getName(), t.getFriendlyName(), false))
            .forEach(requestedAttributes::add);
      }
    }
    else {
      // This is a bit trickier. An SP may declare several entity categories, and the IdP may choose to deliver
      // attributes according to only one of those. In these cases we must think about the required-flag and possibly
      // set it to false even if the category states true.
      //
      final Map<String, List<RequestedAttribute>> candidates = new HashMap<>();
      for (final ServiceEntityCategory sec : serviceCategories) {
        if (sec.getAttributeSet() == null) {
          continue;
        }
        for (final AttributeTemplate at : sec.getAttributeSet().getRequiredAttributes()) {
          List<RequestedAttribute> c = candidates.get(at.getName());
          if (c == null) {
            c = new ArrayList<>();
          }
          c.add(new ImplicitRequestedAttribute(sec.getUri(), at.getName(), at.getFriendlyName(), true));
          candidates.put(at.getName(), c);
        }
        for (final AttributeTemplate at : sec.getAttributeSet().getRecommendedAttributes()) {
          List<RequestedAttribute> c = candidates.get(at.getName());
          if (c == null) {
            c = new ArrayList<>();
          }
          c.add(new ImplicitRequestedAttribute(sec.getUri(), at.getName(), at.getFriendlyName(), false));
          candidates.put(at.getName(), c);
        }
      }
      for (final List<RequestedAttribute> ra : candidates.values()) {
        // If the number of candidates for this attribute is less than the total number of declared
        // entity categories, we must set the isRequired flag to false (since the IdP may deliver according to a
        // category that does not define this attribute).
        //
        if (ra.size() < serviceCategories.size()) {
          ra.get(0).setRequired(false);
          requestedAttributes.add(ra.get(0));
        }
        else {
          // If all isRequired is true, we keep that, otherwise false.
          ra.get(0).setRequired(ra.stream().allMatch(RequestedAttribute::isRequired));
          requestedAttributes.add(ra.get(0));
        }
      }
    }

    log.debug("Extracted requested attributes from EntityCategories - {} [{}]",
        requestedAttributes, authnRequestToken.getLogString());

    return requestedAttributes;
  }

}
