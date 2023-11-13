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

import java.io.File;
import java.security.cert.X509Certificate;

import org.springframework.core.io.Resource;

import lombok.Data;

/**
 * Configuration properties for metadata provider configuration.
 *
 * @author Martin Lindström
 */
@Data
public class MetadataProviderConfigurationProperties {

  /**
   * The location of the metadata. Can be an URL, a file, or even a classpath resource.
   */
  private Resource location;

  /**
   * If the {@code location} is an HTTPS resource, this setting tells whether to skip hostname verification in the TLS
   * connection (useful during testing).
   */
  private Boolean skipHostnameVerification;

  /**
   * If the {@code location} setting is an URL, a "backup location" may be assigned to store downloaded metadata.
   */
  private File backupLocation;

  /**
   * If the {@code location} setting is an URL, setting the MDQ-flag means that the metadata MDQ
   * (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used.
   */
  private Boolean mdq;

  /**
   * The certificate used to validate the metadata.
   */
  private X509Certificate validationCertificate;

  /**
   * If the {@code location} setting is an URL and a HTTP proxy is required this setting configures this proxy.
   */
  private HttpProxy httpProxy;

  /**
   * Configuration properties for an HTTP proxy.
   */
  @Data
  public static class HttpProxy {

    /**
     * The proxy host.
     */
    private String host;

    /**
     * The proxy port.
     */
    private Integer port;

    /**
     * The proxy password (optional).
     */
    private String password;

    /**
     * The proxy user name (optional).
     */
    private String userName;
  }

}
