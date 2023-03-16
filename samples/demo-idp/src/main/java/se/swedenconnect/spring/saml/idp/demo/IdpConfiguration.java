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
package se.swedenconnect.spring.saml.idp.demo;

import java.io.File;

import org.opensaml.saml.saml2.core.NameID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.UrlResource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.thymeleaf.spring5.SpringTemplateEngine;

import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.utils.X509Utils;
import se.swedenconnect.spring.saml.idp.attributes.nameid.DefaultNameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.config.annotation.web.configuration.Saml2IdpConfiguration;
import se.swedenconnect.spring.saml.idp.config.annotation.web.configurers.Saml2IdpConfigurer;
import se.swedenconnect.spring.saml.idp.response.ThymeleafResponsePage;
import se.swedenconnect.spring.saml.idp.settings.CredentialSettings;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataProviderSettings;

/**
 * Configuration class for the demo application.
 *
 * @author Martin Lindström
 */
@Configuration
public class IdpConfiguration {

  @Bean
  @DependsOn("openSAML")
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain samlIdpSecurityFilterChain(final HttpSecurity http, final IdentityProviderSettings settings,
      final SpringTemplateEngine templateEngine)
      throws Exception {

    // Apply the default configuration for the IdP.
    //
    Saml2IdpConfiguration.applyDefaultSecurity(http, null);

    http.getConfigurer(Saml2IdpConfigurer.class)
        // Override the HTML page that is used to post back the SAML response with our own ...
        .responseSender((s) -> s.setResponsePage(new ThymeleafResponsePage(templateEngine, "post-response.html")))
        .authnRequestProcessor(p -> p.authenticationProvider(
            a -> {
              DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(settings.getEntityId());
              f.setDefaultFormat(NameID.TRANSIENT);
              a.nameIDGeneratorFactory(f);
            }));

//    http
//        .anonymous().disable()
//        .rememberMe().disable()
//        .exceptionHandling((exceptions) -> exceptions
//            .authenticationEntryPoint(new RedirectToClientAuthenticationEntryPoint()));

    http.exceptionHandling((exceptions) -> exceptions
        .authenticationEntryPoint(
            new LoginUrlAuthenticationEntryPoint("/login")));

    return http.build();
  }

  @Bean
  WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().antMatchers("/images/**", "/css/**", "/scripts/**", "/webjars/**");
  }

  @Bean
  @Order(2)
  SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http)
      throws Exception {
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated())
        // Form login handles the redirect to the login page from the
        // authorization server filter chain
        .formLogin(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  UserDetailsService userDetailsService() {
    UserDetails userDetails = User.withDefaultPasswordEncoder()
        .username("user")
        .password("password")
        .roles("USER")
        .build();

    return new InMemoryUserDetailsManager(userDetails);
  }

  private PkiCredential getCredential(final String alias) throws Exception {
    KeyStoreCredential cred = new KeyStoreCredential(new ClassPathResource("idp-credentials.jks"),
        "secret".toCharArray(), alias, "secret".toCharArray());
    cred.afterPropertiesSet();
    return cred;
  }

  @Bean
  IdentityProviderSettings identityProviderSettings() throws Exception {
    return IdentityProviderSettings.builder()
        .entityId("https://demo.swedenconnect.se/idp")
        .credentials(CredentialSettings.builder()
            .signCredential(this.getCredential("sign"))
            .encryptCredential(this.getCredential("encrypt"))
            .metadataSignCredential(this.getCredential("metadata"))
            .build())
        .metadataProviderConfiguration(MetadataProviderSettings.builder()
            .location(new UrlResource("https://eid.svelegtest.se/metadata/mdx/role/sp.xml"))
            .backupLocation(new File("target/metadata-backup.xml"))
            .validationCertificate(
                X509Utils.decodeCertificate(new ClassPathResource("sandbox-metadata.crt").getInputStream()))
            .build())
        .build();
  }

  @Bean("openSAML")
  OpenSAMLInitializer openSAML() throws Exception {
    OpenSAMLInitializer.getInstance()
        .initialize(
            new OpenSAMLSecurityDefaultsConfig(new SwedishEidSecurityConfiguration()),
            new OpenSAMLSecurityExtensionConfig());
    return OpenSAMLInitializer.getInstance();
  }

}
