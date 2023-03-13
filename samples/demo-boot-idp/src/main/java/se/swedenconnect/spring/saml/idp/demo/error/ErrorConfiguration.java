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
package se.swedenconnect.spring.saml.idp.demo.error;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.WebProperties.Resources;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcProperties;
import org.springframework.boot.autoconfigure.web.servlet.error.DefaultErrorViewResolver;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({ WebProperties.class, WebMvcProperties.class })
public class ErrorConfiguration {

  private final ApplicationContext applicationContext;

  private final Resources resources;
  
  public ErrorConfiguration(ApplicationContext applicationContext, WebProperties webProperties) {
    this.applicationContext = applicationContext;
    this.resources = webProperties.getResources();
  }

  @Bean
  Saml2IdpErrorAttributes errorAttributes() {
    return new Saml2IdpErrorAttributes();
  }

  @ConditionalOnMissingBean
  @Bean
  DefaultErrorViewResolver conventionErrorViewResolver() {
    return new DefaultErrorViewResolver(this.applicationContext, this.resources);
  }
  
  @ConditionalOnMissingBean
  @Bean
  Saml2IdpErrorViewResolver saml2IdpErrorViewResolver() {
    return new Saml2IdpErrorViewResolver(this.applicationContext, this.resources);
  }

}
