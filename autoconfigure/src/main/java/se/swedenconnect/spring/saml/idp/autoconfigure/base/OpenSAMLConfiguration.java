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
package se.swedenconnect.spring.saml.idp.autoconfigure.base;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

/**
 * Configuration class for initializing OpenSAML.
 */
@AutoConfiguration
public class OpenSAMLConfiguration {

  /**
   * Gets the OpenSAML initializer (which is needed for SAML support)
   *
   * @return OpenSAMLInitializer
   * @throws Exception for init errors
   */
  @ConditionalOnMissingBean
  @Bean("openSAML")
  OpenSAMLInitializer openSAML() throws Exception {
    OpenSAMLInitializer.getInstance()
        .initialize(
            new OpenSAMLSecurityDefaultsConfig(new SwedishEidSecurityConfiguration()),
            new OpenSAMLSecurityExtensionConfig());
    return OpenSAMLInitializer.getInstance();
  }

}
