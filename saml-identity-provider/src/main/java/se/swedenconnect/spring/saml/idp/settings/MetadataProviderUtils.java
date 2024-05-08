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
package se.swedenconnect.spring.saml.idp.settings;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.httpclient.HttpClientBuilder;
import net.shibboleth.shared.httpclient.HttpClientSupport;
import net.shibboleth.shared.httpclient.TLSSocketFactoryBuilder;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.xml.XMLParserException;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.UrlResource;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;
import se.swedenconnect.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.CompositeMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MDQMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.StaticMetadataProvider;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.TrustManager;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Utility methods for handling metadata providers.
 *
 * @author Martin Lindström
 */
@Slf4j
public class MetadataProviderUtils {

  /**
   * Based on one or more {@link MetadataProviderSettings} object(s) a {@link MetadataResolver} is created.
   *
   * @param config configuration
   * @return a {@link MetadataResolver}
   */
  public static MetadataResolver createMetadataResolver(final MetadataProviderSettings[] config) {
    try {
      final List<MetadataProvider> providers = new ArrayList<>();
      for (final MetadataProviderSettings md : config) {
        final AbstractMetadataProvider provider;
        if (md.getLocation() == null) {
          throw new IllegalArgumentException("Missing location for metadata provider");
        }
        if (md.getLocation() instanceof final UrlResource urlResource && !urlResource.isFile()) {
          if (md.getBackupLocation() == null) {
            log.warn("No backup-location for metadata source {} - Using a backup file is strongly recommended",
                md.getLocation());
          }

          if (md.getMdq() != null && md.getMdq()) {
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
        else if (md.getLocation() instanceof FileSystemResource) {
          provider = new FilesystemMetadataProvider(md.getLocation().getFile());
        }
        else {
          final Document doc = Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool())
              .parse(md.getLocation().getInputStream());
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
   * Creates an HTTP client to use for the {@link MetadataResolver}.
   *
   * @return a HttpClient
   */
  private static HttpClient createHttpClient(final MetadataProviderSettings config) {
    try {
      final List<TrustManager> managers = List.of(HttpClientSupport.buildNoTrustX509TrustManager());
      final HostnameVerifier hnv = Optional.ofNullable(config.getSkipHostnameVerification()).orElse(false)
          ? new NoopHostnameVerifier()
          : new DefaultHostnameVerifier();

      final HttpClientBuilder builder = new HttpClientBuilder();
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

  // Hidden ctor
  private MetadataProviderUtils() {
  }

}
