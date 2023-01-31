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
package se.swedenconnect.spring.saml.idp.config.annotation.web.configurers;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.TrustManager;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.UrlResource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.httpclient.HttpClientSupport;
import net.shibboleth.utilities.java.support.httpclient.TLSSocketFactoryBuilder;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.swedenconnect.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.CompositeMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MDQMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.StaticMetadataProvider;
import se.swedenconnect.spring.saml.idp.settings.CredentialSettings;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataProviderSettings;

/**
 * An {@link AbstractHttpConfigurer} for SAML2 Identity Provider support.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2IdpConfigurer
    extends AbstractHttpConfigurer<Saml2IdpConfigurer, HttpSecurity> {

  /** The configurers for the SAML2 Identity Provider. */
  private final Map<Class<? extends AbstractSaml2Configurer>, AbstractSaml2Configurer> configurers =
      this.createConfigurers();

  /** The endpoints matcher. */
  private RequestMatcher endpointsMatcher;

  /**
   * Configures the IdP metadata endpoint.
   *
   * @param customizer the {@link Customizer} providing access to the {@link Saml2IdpMetadataEndpointConfigurer}
   * @return the {@link Saml2IdpConfigurer} for further configuration
   */
  public Saml2IdpConfigurer idpMetadataEndpoint(
      final Customizer<Saml2IdpMetadataEndpointConfigurer> customizer) {
    customizer.customize(this.getConfigurer(Saml2IdpMetadataEndpointConfigurer.class));
    return this;
  }

  /**
   * Returns a {@link RequestMatcher} for the SAML Identity Provider endpoints.
   *
   * @return a {@link RequestMatcher} for the SAML Identity Provider endpoints
   */
  public RequestMatcher getEndpointsMatcher() {
    // Use a deferred RequestMatcher since endpointsMatcher is constructed in init(HttpSecurity).
    //
    return (request) -> this.endpointsMatcher.matches(request);
  }

  /** {@inheritDoc} */
  @Override
  public void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings identityProviderSettings =
        Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    validateIdentityProviderSettings(identityProviderSettings);
    
    // Metadata resolver ...
    //
    if (identityProviderSettings.getMetadataProvider() != null) {
      httpSecurity.setSharedObject(MetadataResolver.class, identityProviderSettings.getMetadataProvider()); 
    }
    else {
      httpSecurity.setSharedObject(MetadataResolver.class, 
          createMetadataResolver(identityProviderSettings.getMetadataProviderConfiguration()));
    }

    final List<RequestMatcher> requestMatchers = new ArrayList<>();
    this.configurers.values().forEach(configurer -> {
      configurer.init(httpSecurity);
      requestMatchers.add(configurer.getRequestMatcher());
    });
//    requestMatchers.add(new AntPathRequestMatcher(
//        authorizationServerSettings.getJwkSetEndpoint(), HttpMethod.GET.name()));
    this.endpointsMatcher = new OrRequestMatcher(requestMatchers);

    // TODO: Change
//    ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
//        httpSecurity.getConfigurer(ExceptionHandlingConfigurer.class);
//    if (exceptionHandling != null) {
//      exceptionHandling.defaultAuthenticationEntryPointFor(
//          new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
//          new OrRequestMatcher(
//              getRequestMatcher(OAuth2TokenEndpointConfigurer.class),
//              getRequestMatcher(OAuth2TokenIntrospectionEndpointConfigurer.class),
//              getRequestMatcher(OAuth2TokenRevocationEndpointConfigurer.class)));
//    }
  }

  /** {@inheritDoc} */
  @Override
  public void configure(final HttpSecurity httpSecurity) {
    this.configurers.values().forEach(configurer -> configurer.configure(httpSecurity));

    final IdentityProviderSettings identityProviderSettings =
        Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);

    // Add context filter ...
    //
    final Saml2IdpContextFilter contextFilter = new Saml2IdpContextFilter(identityProviderSettings);
    httpSecurity.addFilterAfter(this.postProcess(contextFilter), SecurityContextHolderFilter.class);

    // TODO
  }

  /**
   * Creates the configurers for the SAML2 Identity Provider.
   *
   * @return a map of configurers
   */
  private Map<Class<? extends AbstractSaml2Configurer>, AbstractSaml2Configurer> createConfigurers() {
    final Map<Class<? extends AbstractSaml2Configurer>, AbstractSaml2Configurer> configurers = new LinkedHashMap<>();
    configurers.put(Saml2IdpMetadataEndpointConfigurer.class,
        new Saml2IdpMetadataEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2ClientAuthenticationConfigurer.class, new OAuth2ClientAuthenticationConfigurer(this::postProcess));
//    configurers.put(OAuth2AuthorizationServerMetadataEndpointConfigurer.class, new OAuth2AuthorizationServerMetadataEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2AuthorizationEndpointConfigurer.class, new OAuth2AuthorizationEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2TokenEndpointConfigurer.class, new OAuth2TokenEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2TokenIntrospectionEndpointConfigurer.class, new OAuth2TokenIntrospectionEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2TokenRevocationEndpointConfigurer.class, new OAuth2TokenRevocationEndpointConfigurer(this::postProcess));
    return configurers;
  }

  @SuppressWarnings("unchecked")
  private <T> T getConfigurer(final Class<T> type) {
    return (T) this.configurers.get(type);
  }

  private <T extends AbstractSaml2Configurer> void addConfigurer(final Class<T> configurerType, final T configurer) {
    this.configurers.put(configurerType, configurer);
  }

  private <T extends AbstractSaml2Configurer> RequestMatcher getRequestMatcher(final Class<T> configurerType) {
    final T configurer = this.getConfigurer(configurerType);
    return configurer != null ? configurer.getRequestMatcher() : null;
  }

  /**
   * Validates that {@link IdentityProviderSettings} has been set up so that the Identity Provider can function.
   *
   * @param identityProviderSettings the settings to validate
   */
  public static void validateIdentityProviderSettings(final IdentityProviderSettings identityProviderSettings)
      throws IllegalArgumentException {
    if (!StringUtils.hasText(identityProviderSettings.getEntityId())) {
      throw new IllegalArgumentException("Identity Provider entityID must be assigned");
    }
    if (identityProviderSettings.getBaseUrl().endsWith("/")) {
      throw new IllegalArgumentException("Base URL must not end with /");
    }
    if (identityProviderSettings.getHokBaseUrl() != null
        && identityProviderSettings.getHokBaseUrl().endsWith("/")) {
      throw new IllegalArgumentException("HoK base URL must not end with /");
    }

    // Assert credentials
    //
    final CredentialSettings credentials = identityProviderSettings.getCredentials();
    if (credentials == null) {
      throw new IllegalArgumentException("No Identity Provider credentials have been assigned");
    }
    final boolean defaultCredentialAssigned = credentials.getDefaultCredential() != null;
    if (credentials.getSignCredential() == null && !defaultCredentialAssigned) {
      throw new IllegalArgumentException("No signing credential has been assigned (and no default)");
    }
    if (credentials.getEncryptCredential() == null && !defaultCredentialAssigned) {
      throw new IllegalArgumentException("No signing credential has been assigned (and no default)");
    }

    // Assert endpoints
    //
    if (!identityProviderSettings.getEndpoints().getMetadataEndpoint().startsWith("/")) {
      throw new IllegalArgumentException("Invalid endpoint - metadata path must begin with /");
    }

    // Metadata providers
    //
    if (identityProviderSettings.getMetadataProvider() != null) {
      final MetadataProviderSettings[] mdConfig = identityProviderSettings.getMetadataProviderConfiguration();
      if (mdConfig == null || mdConfig.length == 0) {
        throw new IllegalArgumentException("No metadata providers have been configured");
      }
      
      
      for (int i = 0; i < mdConfig.length; i++) {
        final MetadataProviderSettings md = mdConfig[i];
        if (md.getLocation() == null) {
          throw new IllegalArgumentException("Missing location for metadata provider at position " + i);
        }
        if (UrlResource.class.isInstance(md.getLocation())) {
          if (md.getBackupLocation() == null) {
            log.warn("No backup-location for metadata source {} - Using a backup file is strongly recommended",
                md.getLocation());
          }
          if (md.getValidationCertificate() == null) {
            log.warn("No validation certificate assigned for metadata source {} "
                + "- downloaded metadata can not be trusted", md.getLocation());
          }
          if (md.getHttpProxy() != null) {
            if (md.getHttpProxy().getHost() == null || md.getHttpProxy().getPort() == null) {
              throw new IllegalArgumentException("Invalid HTTP proxy configuration for metadata source"
                  + md.getLocation());
            }
          }
        }
      }
    }
  }

  private static MetadataResolver createMetadataResolver(final MetadataProviderSettings[] config) {
    try {
      final List<MetadataProvider> providers = new ArrayList<>();
      for (MetadataProviderSettings md : config) {
        AbstractMetadataProvider provider = null;
        if (md.getLocation() == null) {
          throw new IllegalArgumentException("Missing location for metadata provider");
        }
        if (UrlResource.class.isInstance(md.getLocation())) {
          if (md.getBackupLocation() == null) {
            log.warn("No backup-location for metadata source {} - Using a backup file is strongly recommended",
                md.getLocation());
          }

          if (md.getMdq() != null && md.getMdq().booleanValue()) {
            provider = new MDQMetadataProvider(md.getLocation().getURL().toString(), createHttpClient(md),
                preProcessBackupDirectory(md.getBackupLocation()));
          }
          else {
            provider = new HTTPMetadataProvider(md.getLocation().getURL().toString(),
                preProcessBackupFile(md.getBackupLocation()), createHttpClient(md));
          }
          if (md.getValidationCertificate() != null) {
            provider.setSignatureVerificationCertificate(md.getValidationCertificate());
          }
          else {
            log.warn("No validation certificate assigned for metadata source {} "
                + "- downloaded metadata can not be trusted", md.getLocation());
          }
        }
        else if (FileSystemResource.class.isInstance(md.getLocation())) {
          provider = new FilesystemMetadataProvider(md.getLocation().getFile());
        }
        else {
          final Document doc =
              XMLObjectProviderRegistrySupport.getParserPool().parse(md.getLocation().getInputStream());
          provider = new StaticMetadataProvider(doc.getDocumentElement());
        }
        provider.setPerformSchemaValidation(false);
        provider.initialize();
        providers.add(provider);
      }
      if (providers.size() > 1) {
        final CompositeMetadataProvider compositeProvider =
            new CompositeMetadataProvider("composite-provider", providers);
        compositeProvider.initialize();
        return compositeProvider.getMetadataResolver();
      }
      else {
        return providers.get(0).getMetadataResolver();
      }
    }
    catch (final ResolverException | ComponentInitializationException | IOException | XMLParserException e) {
      throw new IllegalArgumentException("Failed to initialize metadata provider - " + e.getMessage(), e);
    }
  }

  /**
   * Creates a HTTP client to use for the {@link MetadataResolver}.
   *
   * @return a HttpClient
   */
  private static HttpClient createHttpClient(final MetadataProviderSettings config) {
    try {
      final List<TrustManager> managers = Arrays.asList(HttpClientSupport.buildNoTrustX509TrustManager());
      final HostnameVerifier hnv = new DefaultHostnameVerifier();

      HttpClientBuilder builder = new HttpClientBuilder();
      builder.setUseSystemProperties(true);
      if (config.getHttpProxy() != null) {
        if (config.getHttpProxy().getHost() == null || config.getHttpProxy().getPort() == null) {
          throw new IllegalArgumentException("Invalid HTTP proxy configuration for metadata source " +
              config.getLocation());
        }
        builder.setConnectionProxyHost(config.getHttpProxy().getHost());
        builder.setConnectionProxyPort(config.getHttpProxy().getPort());
        if (StringUtils.hasText(config.getHttpProxy().getUserName())) {
          builder.setConnectionProxyUsername(config.getHttpProxy().getUserName());
        }
        if (StringUtils.hasText(config.getHttpProxy().getPassword())) {
          builder.setConnectionProxyPassword(config.getHttpProxy().getPassword());
        }
      }
      builder.setTLSSocketFactory(new TLSSocketFactoryBuilder()
          .setHostnameVerifier(hnv)
          .setTrustManagers(managers)
          .build());

      return builder.buildClient();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to initialize HttpClient", e);
    }
  }
  
  /**
   * Makes sure that all parent directories for the supplied file exists and returns the backup file as an absolute
   * path.
   *
   * @param backupFile the backup file
   * @return the absolute path of the backup file
   */
  private static String preProcessBackupFile(final File backupFile) {
    if (backupFile == null) {
      return null;
    }
    preProcessBackupDirectory(backupFile.getParentFile());
    return backupFile.getAbsolutePath();
  }

  /**
   * Makes sure that all parent directories exists and returns the directory as an absolute path.
   *
   * @param backupDirectory the backup directory
   * @return the absolute path of the backup directory
   */
  private static String preProcessBackupDirectory(final File backupDirectory) {
    if (backupDirectory == null) {
      return null;
    }
    try {
      final Path path = backupDirectory.toPath();
      Files.createDirectories(path);
      return path.toFile().getAbsolutePath();
    }
    catch (final IOException e) {
      throw new IllegalArgumentException("Invalid backup-location");
    }
  }


}
