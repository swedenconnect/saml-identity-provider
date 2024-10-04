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
package se.swedenconnect.spring.saml.idp.metadata;

import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryRegistry;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryRegistryImpl;

import java.util.List;

/**
 * Support class for handling entity categories.
 *
 * @author Martin Lindström
 */
public class EntityCategoryHelper {

  private static EntityCategoryRegistry registry;

  private EntityCategoryHelper() {
  }

  /**
   * Gets all registered entity categories from the Swedish eID Framework, see <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
   * Categories for the Swedish eID Framework</a>.
   *
   * @return an {@link EntityCategoryRegistry}
   */
  public static EntityCategoryRegistry getDefaultEntityCategoryRegistry() {
    if (registry == null) {
      registry = new EntityCategoryRegistryImpl(List.of(
          EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER,
          EntityCategoryConstants.GENERAL_CATEGORY_SECURE_AUTHENTICATOR_BINDING,
          EntityCategoryConstants.SERVICE_CONTRACT_CATEGORY_EID_CHOICE_2017,
          EntityCategoryConstants.SERVICE_CONTRACT_CATEGORY_SWEDEN_CONNECT,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_EIDAS_NATURAL_PERSON,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_NAME,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_ORGID,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_PNR,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_NAME,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_ORGID,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA4_NAME,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA4_ORGID,
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA4_PNR,
          EntityCategoryConstants.SERVICE_PROPERTY_CATEGORY_MOBILE_AUTH,
          EntityCategoryConstants.SERVICE_TYPE_CATEGORY_PRIVATE_SECTOR_SP,
          EntityCategoryConstants.SERVICE_TYPE_CATEGORY_PUBLIC_SECTOR_SP,
          EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE));
    }
    return registry;
  }

}
