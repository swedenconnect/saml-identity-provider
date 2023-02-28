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
package se.swedenconnect.spring.saml.idp.config.annotation.web.configurers;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Abstract base configurer for setting up objects, such as {@link AuthenticationProvider} instances, as part of the
 * Spring Security configuration.
 *
 * @author Martin Lindström
 */
abstract class AbstractObjectConfigurer<T> {

  /**
   * Initializes the configurer and the underlying object.
   *
   * @param httpSecurity the HttpSecurity object
   */
  abstract void init(final HttpSecurity httpSecurity);

  /**
   * Gets the object being configured.
   *
   * @param httpSecurity the HttpSecurity object to configure
   * @return the created and configured object
   */
  abstract T getObject(final HttpSecurity httpSecurity);

}
