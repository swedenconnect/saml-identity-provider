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
package se.swedenconnect.spring.saml.idp.autoconfigure.error;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.autoconfigure.condition.SearchStrategy;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.WebProperties.Resources;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcProperties;
import org.springframework.boot.autoconfigure.web.servlet.error.DefaultErrorViewResolver;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.DispatcherServlet;

import jakarta.servlet.Servlet;

/**
 * IdP specific {@link EnableAutoConfiguration Auto-configuration} to render errors via an MVC error controller.
 *
 * @author Martin Lindström
 */
@AutoConfiguration(before = { WebMvcAutoConfiguration.class, ErrorMvcAutoConfiguration.class })
@ConditionalOnWebApplication(type = Type.SERVLET)
@ConditionalOnClass({ Servlet.class, DispatcherServlet.class })
@EnableConfigurationProperties({ ServerProperties.class, WebMvcProperties.class })
public class Saml2IdpErrorAutoConfiguration {

  /**
   * Path of the IdP error view name.
   */
  @Value("${saml.idp.error.view:/error/idp}")
  private String errorViewName = "/error/idp";

  private final ApplicationContext applicationContext;

  private final Resources resources;

  public Saml2IdpErrorAutoConfiguration(final ApplicationContext applicationContext,
      final WebProperties webProperties) {
    this.applicationContext = applicationContext;
    this.resources = webProperties.getResources();
  }

  @Bean
  @ConditionalOnMissingBean(value = Saml2IdpErrorAttributes.class, search = SearchStrategy.CURRENT)
  Saml2IdpErrorAttributes errorAttributes() {
    return new Saml2IdpErrorAttributes();
  }

  @Bean
  @ConditionalOnBean(DispatcherServlet.class)
  @ConditionalOnMissingBean(DefaultErrorViewResolver.class)
  DefaultErrorViewResolver conventionErrorViewResolver() {
    return new DefaultErrorViewResolver(this.applicationContext, this.resources);
  }

  @Bean
  @ConditionalOnBean(DispatcherServlet.class)
  @ConditionalOnMissingBean(Saml2IdpErrorViewResolver.class)
  Saml2IdpErrorViewResolver saml2IdpErrorViewResolver() {
    final Saml2IdpErrorViewResolver resolver = new Saml2IdpErrorViewResolver(this.applicationContext);
    resolver.setIdpErrorViewName(this.errorViewName);
    return resolver;
  }

}
