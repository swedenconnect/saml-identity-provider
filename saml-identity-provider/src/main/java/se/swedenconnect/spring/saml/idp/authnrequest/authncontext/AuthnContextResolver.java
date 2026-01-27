/*
 * Copyright 2023-2026 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.authnrequest.authncontext;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A bean that resolves the received contents of a {@code RequestedAuthnContext} element.
 *
 * @author Martin Lindström
 */
@Slf4j
public class AuthnContextResolver {

  /**
   * A map where each URI key is mapped to a list of minimum authentication context classes, i.e., if X is given with
   * minimum comparison, this may be resolved to X, Y, and Z.
   */
  @Nullable
  private Map<String, List<String>> minimumMapping;

  /**
   * A map where each URI key is mapped to a list of "better" authentication context classes, i.e., if X is given with
   * better comparison, this may be resolved to Y and Z.
   */
  @Nullable
  private Map<String, List<String>> betterMapping;

  /**
   * A map where each URI key is mapped to a list of "maximum" authentication context classes, i.e., if Y is given with
   * maximum comparison, this may be resolved to X and Y.
   */
  @Nullable
  private Map<String, List<String>> maximumMapping;

  /**
   * Default constructor.
   */
  public AuthnContextResolver() {
  }

  /**
   * Resolves the authentication context class references based on the provided {@link RequestedAuthnContext} and its
   * comparison type. Different comparison types such as "exact", "minimum", "better", or "maximum" influence the
   * resolution logic. In the event of a misconfiguration or unsupported comparison type, an exception is thrown. If no
   * {@link RequestedAuthnContext} is provided, the method returns an empty list.
   *
   * @param requestedAuthnContext the requested authentication context, which includes the comparison type and
   *     authentication context class references; may be {@code null}.
   * @param logString a string used for logging purposes, providing additional context for debugging; must not be
   *     {@code null}.
   * @return a list of resolved authentication context class references based on the comparison type, or an empty list
   *     if {@code requestedAuthnContext} is {@code null}.
   * @throws Saml2ErrorStatusException if the comparison type is unsupported, or if mappings required for resolution
   *     are not properly configured.
   */
  public List<String> resolve(
      @Nullable final RequestedAuthnContext requestedAuthnContext, @Nonnull final String logString)
      throws Saml2ErrorStatusException {
    if (requestedAuthnContext == null) {
      return Collections.emptyList();
    }
    if (requestedAuthnContext.getAuthnContextClassRefs().isEmpty()
        && !requestedAuthnContext.getAuthnContextDeclRefs().isEmpty()) {
      final String msg = "Invalid AuthnRequest - AuthnContextDeclRefs not supported in RequestedAuthnContext";
      log.info("{} [{}]", msg, logString);
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
    }

    final List<String> requestedUris = requestedAuthnContext.getAuthnContextClassRefs().stream()
        .map(XSURI::getURI)
        .collect(Collectors.toList());

    if (AuthnContextComparisonTypeEnumeration.EXACT == requestedAuthnContext.getComparison()
        || requestedAuthnContext.getComparison() == null) {
      return requestedUris;
    }
    if (AuthnContextComparisonTypeEnumeration.MINIMUM == requestedAuthnContext.getComparison()) {
      if (this.minimumMapping == null) {
        final String msg = "Invalid AuthnRequest - minimum comparison for RequestedAuthnContext is not supported";
        log.info("{} [{}]", msg, logString);
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
      }
      final List<String> resolvedUris = new ArrayList<>();
      for (final String uri : requestedUris) {
        final List<String> mappings = this.minimumMapping.get(uri);
        if (mappings == null) {
          continue;
        }
        mappings.stream().filter(u -> !resolvedUris.contains(u)).forEach(resolvedUris::add);
      }
      if (resolvedUris.isEmpty()) {
        final String msg =
            "Invalid AuthnRequest - no configuration for minimum comparison URI:s in RequestedAuthnContext";
        log.info("{} [{}]", msg, logString);
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
      }
      log.debug("Resolved minimum comparison URI:s: {} [{}]", resolvedUris, logString);
      return resolvedUris;
    }

    if (AuthnContextComparisonTypeEnumeration.BETTER == requestedAuthnContext.getComparison()) {
      if (this.betterMapping == null) {
        final String msg = "Invalid AuthnRequest - better comparison for RequestedAuthnContext is not supported";
        log.info("{} [{}]", msg, logString);
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
      }
      final List<List<String>> resolvedMappings = new ArrayList<>();
      for (final String uri : requestedUris) {
        final List<String> mappings = this.betterMapping.get(uri);
        resolvedMappings.add(mappings != null ? mappings : Collections.emptyList());
      }
      final List<String> resolvedUris;
      if (resolvedMappings.isEmpty()) {
        resolvedUris = Collections.emptyList();
      }
      else {
        resolvedUris = new ArrayList<>(resolvedMappings.get(0));
        for (int i = 1; i < resolvedMappings.size(); i++) {
          resolvedUris.retainAll(resolvedMappings.get(i));
        }
      }

      if (resolvedUris.isEmpty()) {
        final String msg =
            "Invalid AuthnRequest - no configuration for better comparison URI:s in RequestedAuthnContext";
        log.info("{} [{}]", msg, logString);
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
      }
      log.debug("Resolved better comparison URI:s: {} [{}]", resolvedUris, logString);
      return resolvedUris;
    }

    if (AuthnContextComparisonTypeEnumeration.MAXIMUM == requestedAuthnContext.getComparison()) {
      if (this.maximumMapping == null) {
        final String msg = "Invalid AuthnRequest - maximum comparison for RequestedAuthnContext is not supported";
        log.info("{} [{}]", msg, logString);
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
      }
      final List<String> resolvedUris = new ArrayList<>();
      for (final String uri : requestedUris) {
        final List<String> mappings = this.maximumMapping.get(uri);
        if (mappings != null) {
          mappings.stream().filter(u -> !resolvedUris.contains(u)).forEach(resolvedUris::add);
        }
      }
      resolvedUris.removeAll(requestedUris);

      if (resolvedUris.isEmpty()) {
        final String msg =
            "Invalid AuthnRequest - no configuration for maximum comparison URI:s in RequestedAuthnContext";
        log.info("{} [{}]", msg, logString);
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
      }
      log.debug("Resolved maximum comparison URI:s: {} [{}]", resolvedUris, logString);
      return resolvedUris;
    }

    final String msg =
        "Invalid AuthnRequest - unknown comparison in RequestedAuthnContext";
    log.info("{} [{}]", msg, logString);
    throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
  }

  /**
   * Sets the map representing the minimum authentication context class mappings. Each URI key in the map is associated
   * with a list of authentication context classes that correspond to a "minimum" comparison. For example, if a context
   * X is given with a minimum requirement, it may resolve to X, Y, and Z.
   *
   * @param minimumMapping a map where the key is a URI string and the value is a list of corresponding
   *     authentication context classes, or {@code null} if no minimum mapping is configured
   */
  public void setMinimumMapping(@Nullable final Map<String, List<String>> minimumMapping) {
    this.minimumMapping = minimumMapping;
  }

  /**
   * Sets the map representing the "better" authentication context class mappings. Each URI key in the map is associated
   * with a list of authentication context classes that correspond to a "better" comparison. For example, if a context X
   * is given with a "better" requirement, it may resolve to Y and Z.
   *
   * @param betterMapping a map where the key is a URI string and the value is a list of corresponding
   *     authentication context classes, or {@code null} if no better mapping is configured
   */
  public void setBetterMapping(@Nullable final Map<String, List<String>> betterMapping) {
    this.betterMapping = betterMapping;
  }

  /**
   * Sets the map representing the "maximum" authentication context class mappings. Each URI key in the map is
   * associated with a list of authentication context classes that correspond to a "maximum" comparison. For example, if
   * a context Y is given with a maximum requirement, it may resolve to X and Y.
   *
   * @param maximumMapping a map where the key is a URI string and the value is a list of corresponding
   *     authentication context classes, or {@code null} if no maximum mapping is configured
   */
  public void setMaximumMapping(@Nullable final Map<String, List<String>> maximumMapping) {
    this.maximumMapping = maximumMapping;
  }

}
