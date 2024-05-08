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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import lombok.Getter;
import lombok.Setter;
import org.springframework.core.io.Resource;

import java.io.File;
import java.security.cert.X509Certificate;

/**
 * Configuration properties for metadata provider configuration.
 *
 * @author Martin Lindström
 */
public class MetadataProviderConfigurationProperties {

  /**
   * The location of the metadata. Can be a URL, a file, or even a classpath resource.
   */
  @Setter
  @Getter
  private Resource location;

  /**
   * If the {@code location} is an HTTPS resource, this setting tells whether to skip hostname verification in the TLS
   * connection (useful during testing).
   */
  @Setter
  @Getter
  private Boolean skipHostnameVerification;

  /**
   * If the {@code location} setting is a URL, a "backup location" may be assigned to store downloaded metadata.
   */
  @Setter
  @Getter
  private File backupLocation;

  /**
   * If the {@code location} setting is a URL, setting the MDQ-flag means that the metadata MDQ
   * (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used.
   */
  @Setter
  @Getter
  private Boolean mdq;

  /**
   * The certificate used to validate the metadata.
   */
  @Setter
  @Getter
  private X509Certificate validationCertificate;

  /**
   * If the {@code location} setting is a URL and an HTTP proxy is required this setting configures this proxy.
   */
  @Setter
  @Getter
  private HttpProxy httpProxy;

  /**
   * Configuration properties for an HTTP proxy.
   */
  public static class HttpProxy {

    /**
     * The proxy host.
     */
    @Setter
    @Getter
    private String host;

    /**
     * The proxy port.
     */
    @Setter
    @Getter
    private Integer port;

    /**
     * The proxy password (optional).
     */
    @Setter
    @Getter
    private String password;

    /**
     * The proxy username (optional).
     */
    @Setter
    @Getter
    private String userName;
  }

}
