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

import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.convert.converter.Converter;

import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;
import se.swedenconnect.spring.saml.idp.metadata.PropertyToEntityDescriptorConverter;

/**
 * Configuration class that registers converters for Spring converters needed to applying properties to SignService
 * configuration properties classes.
 */
@AutoConfiguration
public class ConvertersConfiguration {

  /**
   * Creates the bean the allows us to use property values that are referencing certificate resources and get the
   * {@link X509Certificate} injected.
   *
   * @return a PropertyToX509CertificateConverter bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

  /**
   * Creates the bean the allows us to use property values that are referencing EntityDescriptor resources and get the
   * {@link EntityDescriptor} injected.
   *
   * @return a PropertyToEntityDescriptorConverter bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  @DependsOn("openSAML")
  PropertyToEntityDescriptorConverter propertyToEntityDescriptorConverter() {
    return new PropertyToEntityDescriptorConverter();
  }

  /**
   * Creates a converter from a string to a {@link LocalizedString}.
   *
   * @return a LocalizedStringConverter bean
   */
  @Bean
  @ConfigurationPropertiesBinding
  Converter<String, LocalizedString> localizedStringConverter() {
    return new Converter<String, LocalizedString>() {
      @Override
      public LocalizedString convert(@Nonnull final String source) {
        return new LocalizedString(source);
      }
    };
  }

}
