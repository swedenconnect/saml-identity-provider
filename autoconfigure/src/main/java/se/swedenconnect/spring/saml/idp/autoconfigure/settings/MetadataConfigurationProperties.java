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

import org.springframework.core.io.Resource;

import lombok.Data;

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
   * The declared entity categories, see <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
   * Categories for the Swedish eID Framework</a>.
   */
  private List<String> entityCategories;

}
