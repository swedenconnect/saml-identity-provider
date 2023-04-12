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
package se.swedenconnect.spring.saml.idp.config.configurers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import se.swedenconnect.spring.saml.idp.config.Saml2IdpConfiguration;

/**
 * Since Spring have deprecated the use of {@code WebSecurityConfigurerAdapter} and thinks that the setup of a
 * {@link SecurityFilterChain} should be component based, we have lost the easy way of modifying a Spring Security
 * configuration without having to dig really deep into how a particular feature is configured. So, we introduce the
 * {@link Saml2IdpConfigurerAdapter} that may be implemented in order to make adjustments to the default SAML IdP
 * settings.
 * <p>
 * Implement any number of {@link Saml2IdpConfigurerAdapter} instances and have them registered as beans. After that
 * {@code Import} the {@link Saml2IdpConfiguration} class and a SAML IdP {@link SecurityFilterChain} is created.
 * </p>
 * 
 * @author Martin Lindström
 */
public interface Saml2IdpConfigurerAdapter {

  /**
   * Configures the settings of the {@link Saml2IdpConfigurer}.
   * 
   * @param http the HTTP security object
   * @param configurer the {@link Saml2IdpConfigurer}
   */
  void configure(final HttpSecurity http, final Saml2IdpConfigurer configurer);

}
