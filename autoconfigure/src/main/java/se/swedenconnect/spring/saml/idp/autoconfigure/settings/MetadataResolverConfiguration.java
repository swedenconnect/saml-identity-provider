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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Setter;
import se.swedenconnect.spring.saml.idp.settings.MetadataProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataProviderUtils;

/**
 * Configuration class that ensures that we have a {@link MetadataResolver} bean.
 *
 * @author Martin Lindström
 */
@Configuration
@EnableConfigurationProperties(IdentityProviderConfigurationProperties.class)
public class MetadataResolverConfiguration {

  @Setter
  @Autowired(required = false)
  private IdentityProviderConfigurationProperties properties;

  @ConditionalOnMissingBean(name = "saml.idp.metadata.Provider")
  @Bean("saml.idp.metadata.Provider")
  MetadataResolver metadataResolver() {
    if (this.properties == null) {
      return null;
    }
    if (this.properties.getMetadataProviders() != null) {
      final MetadataProviderSettings[] settings =
          new MetadataProviderSettings[this.properties.getMetadataProviders().size()];
      int pos = 0;
      for (final MetadataProviderConfigurationProperties p : this.properties.getMetadataProviders()) {
        settings[pos++] = MetadataProviderSettings.builder()
            .location(p.getLocation())
            .skipHostnameVerification(p.getSkipHostnameVerification())
            .backupLocation(p.getBackupLocation())
            .mdq(p.getMdq())
            .validationCertificate(p.getValidationCertificate())
            .httpProxy(p.getHttpProxy() != null
                ? MetadataProviderSettings.HttpProxySettings.builder()
                    .host(p.getHttpProxy().getHost())
                    .port(p.getHttpProxy().getPort())
                    .userName(p.getHttpProxy().getUserName())
                    .password(p.getHttpProxy().getPassword())
                    .build()
                : null)
            .build();
      }
      return MetadataProviderUtils.createMetadataResolver(settings);
    }
    else {
      return null;
    }
  }

}
