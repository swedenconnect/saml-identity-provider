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
package se.swedenconnect.spring.saml.testsp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import se.swedenconnect.spring.saml.testsp.ext.ExtendedSaml2AuthenticationTokenConverter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SamlSpSecurityConfiguration {

  @Autowired
  ExtendedSaml2AuthenticationTokenConverter saml2AuthenticationTokenConverter;

  @Autowired
  OpenSaml5AuthenticationProvider openSaml5AuthenticationProvider;

  @Bean
  SecurityFilterChain samlLoginFilterChain(final HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
            (authorize) -> authorize
                .requestMatchers(HttpMethod.GET, "/private/**").authenticated()
                .requestMatchers(HttpMethod.POST, "/saml/**", "/private/**").authenticated()
                .anyRequest().permitAll())
        .rememberMe(AbstractHttpConfigurer::disable)
        .authenticationProvider(this.openSaml5AuthenticationProvider)
        .saml2Login(login -> login.authenticationConverter(this.saml2AuthenticationTokenConverter))
        .saml2Logout(Customizer.withDefaults())
        .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .cors(Customizer.withDefaults());
    return http.build();
  }

}
