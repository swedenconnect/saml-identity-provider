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
package se.swedenconnect.spring.saml.idp.web.filters;

import java.io.IOException;
import java.util.Objects;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.spring.saml.idp.metadata.Saml2MetadataHttpMessageConverter;

/**
 * A {@code Filter} that processes requests to download the Identity Provider's metadata.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2IdpMetadataEndpointFilter extends OncePerRequestFilter {

  /** Media type for SAML metadata in XML format. */
  public static final MediaType APPLICATION_SAML_METADATA = new MediaType("application", "samlmetadata+xml");

  /** The default endpoint for serving IdP metadata. */
  public static final String DEFAULT_METADATA_ENDPOINT_URI = "/metadata";

  /** The request matcher for the metadata publishing endpoint. */
  private final RequestMatcher requestMatcher;

  /** The container holding the IdP metadata. */
  final EntityDescriptorContainer entityDescriptorContainer;

  /** Converter for writing metadata. */
  private final Saml2MetadataHttpMessageConverter messageConverter = new Saml2MetadataHttpMessageConverter();

  /**
   * Constructor that uses the default endpoint to publish metadata ({@value #DEFAULT_METADATA_ENDPOINT_URI}).
   *
   * @param entityDescriptorContainer the IdP metadata container
   */
  public Saml2IdpMetadataEndpointFilter(final EntityDescriptorContainer entityDescriptorContainer) {
    this(entityDescriptorContainer, DEFAULT_METADATA_ENDPOINT_URI);
  }

  /**
   * Constructor.
   *
   * @param entityDescriptorContainer the IdP metadata container
   * @param endpoint the metadata publishing endpoint
   */
  public Saml2IdpMetadataEndpointFilter(
      final EntityDescriptorContainer entityDescriptorContainer, final String endpoint) {
    this(entityDescriptorContainer, new AntPathRequestMatcher(
        Objects.requireNonNull(endpoint, "endpoint must be set"), HttpMethod.GET.name()));
  }

  /**
   * Constructor.
   *
   * @param entityDescriptorContainer the IdP metadata container
   * @param requestMatcher the request matcher
   */
  public Saml2IdpMetadataEndpointFilter(
      final EntityDescriptorContainer entityDescriptorContainer, final RequestMatcher requestMatcher) {
    this.entityDescriptorContainer =
        Objects.requireNonNull(entityDescriptorContainer, "entityDescriptorContainer must not be null");
    Assert.notNull(requestMatcher, "endpoint must be set");
    this.requestMatcher = requestMatcher;
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(@NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response, @NonNull final FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    log.debug("Request to download metadata from {}", request.getRemoteAddr());
    try {

      // Check if the metadata is up-to-date according to how the container was configured.
      //
      if (this.entityDescriptorContainer.updateRequired(true)) {
        log.debug("Metadata needs to be updated ...");
        this.entityDescriptorContainer.update(true);
        log.debug("Metadata was updated");
      }
      else {
        log.debug("Metadata is up-to-date, using cached metadata");
      }

      final String acceptHeader = request.getHeader("Accept");
      final MediaType contentType =
          (acceptHeader != null && acceptHeader.contains(APPLICATION_SAML_METADATA.toString()))
              ? APPLICATION_SAML_METADATA
              : MediaType.APPLICATION_XML;

      final ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
      this.messageConverter.write(this.entityDescriptorContainer.getDescriptor(), contentType, httpResponse);
    }
    catch (final SignatureException | MarshallingException e) {
      log.error("Failed to return valid metadata", e);
      throw new IOException("Failed to produce SAML metadata", e);
    }

  }

}
