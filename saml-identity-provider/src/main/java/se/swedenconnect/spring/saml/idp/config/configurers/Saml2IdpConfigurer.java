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
package se.swedenconnect.spring.saml.idp.config.configurers;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.component.ComponentInitializationException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.core.io.UrlResource;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseBuilder;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseSender;
import se.swedenconnect.spring.saml.idp.settings.CredentialSettings;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataProviderUtils;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2ErrorResponseProcessingFilter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An {@link AbstractHttpConfigurer} for SAML2 Identity Provider support.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2IdpConfigurer extends AbstractHttpConfigurer<Saml2IdpConfigurer, HttpSecurity> {

  /** The configurers for the SAML2 Identity Provider. */
  private final Map<Class<? extends AbstractSaml2Configurer>, AbstractSaml2Configurer> configurers =
      this.createConfigurers();

  /** The endpoints' matcher. */
  private RequestMatcher endpointsMatcher;

  /**
   * Customizes the IdP metadata endpoint.
   *
   * @param customizer the {@link Customizer} providing access to the {@link Saml2IdpMetadataEndpointConfigurer}
   * @return the {@link Saml2IdpConfigurer} for further configuration
   */
  public Saml2IdpConfigurer idpMetadataEndpoint(final Customizer<Saml2IdpMetadataEndpointConfigurer> customizer) {
    customizer.customize(this.getConfigurer(Saml2IdpMetadataEndpointConfigurer.class));
    return this;
  }

  /**
   * Customizes the {@code AuthnRequest} processor.
   *
   * @param customizer the {@link Customizer} providing access to the {@link Saml2AuthnRequestProcessorConfigurer}
   * @return the {@link Saml2IdpConfigurer} for further configuration
   */
  public Saml2IdpConfigurer authnRequestProcessor(final Customizer<Saml2AuthnRequestProcessorConfigurer> customizer) {
    customizer.customize(this.getConfigurer(Saml2AuthnRequestProcessorConfigurer.class));
    return this;
  }

  /**
   * Customizes the user authentication processor.
   *
   * @param customizer the {@link Customizer} providing access to the {@link Saml2UserAuthenticationConfigurer}
   * @return the {@link Saml2IdpConfigurer} for further configuration
   */
  public Saml2IdpConfigurer userAuthentication(final Customizer<Saml2UserAuthenticationConfigurer> customizer) {
    customizer.customize(this.getConfigurer(Saml2UserAuthenticationConfigurer.class));
    return this;
  }

  /**
   * Customizes the {@link Saml2ResponseBuilder}.
   *
   * @param customizer the {@link Customizer} providing access to the {@link Saml2ResponseBuilder}
   * @return the {@link Saml2IdpConfigurer} for further configuration
   */
  public Saml2IdpConfigurer responseBuilder(final Customizer<Saml2ResponseBuilder> customizer) {
    customizer.customize(Saml2IdpConfigurerUtils.getResponseBuilder(this.getBuilder()));
    return this;
  }

  /**
   * Customizes the {@link Saml2ResponseSender}.
   *
   * @param customizer the {@link Customizer} providing access to the {@link Saml2ResponseSender}
   * @return the {@link Saml2IdpConfigurer} for further configuration
   */
  public Saml2IdpConfigurer responseSender(final Customizer<Saml2ResponseSender> customizer) {
    customizer.customize(Saml2IdpConfigurerUtils.getResponseSender(this.getBuilder()));
    return this;
  }

  /**
   * Returns a {@link RequestMatcher} for the SAML Identity Provider endpoints.
   *
   * @return a {@link RequestMatcher}
   */
  public RequestMatcher getEndpointsMatcher() {
    return (request) -> this.endpointsMatcher.matches(request);
  }

  /** {@inheritDoc} */
  @Override
  public void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings identityProviderSettings =
        Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    validateIdentityProviderSettings(identityProviderSettings);

    // Metadata resolver ...
    //
    MetadataResolver metadataResolver = identityProviderSettings.getMetadataProvider();
    if (metadataResolver != null) {
      httpSecurity.setSharedObject(MetadataResolver.class, metadataResolver);
    }
    else {
      metadataResolver =
          MetadataProviderUtils.createMetadataResolver(identityProviderSettings.getMetadataProviderConfiguration());
      httpSecurity.setSharedObject(MetadataResolver.class, metadataResolver);
    }

    // Signature trust engine ...
    //
    SignatureTrustEngine signatureTrustEngine = httpSecurity.getSharedObject(SignatureTrustEngine.class);
    if (signatureTrustEngine == null) {
      try {
        final PredicateRoleDescriptorResolver roleDescriptorResolver =
            new PredicateRoleDescriptorResolver(metadataResolver);
        roleDescriptorResolver.setRequireValidMetadata(true);
        roleDescriptorResolver.initialize();

        final MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
        metadataCredentialResolver.setKeyInfoCredentialResolver(
            DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
        metadataCredentialResolver.setRoleDescriptorResolver(roleDescriptorResolver);
        metadataCredentialResolver.initialize();

        signatureTrustEngine = new ExplicitKeySignatureTrustEngine(metadataCredentialResolver,
            DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());

        httpSecurity.setSharedObject(SignatureTrustEngine.class, signatureTrustEngine);
      }
      catch (final ComponentInitializationException e) {
        throw new InternalAuthenticationServiceException("Failed to initialize MetadataCredentialResolver", e);
      }
    }

    // Configurers ...
    //
    final RequestMatcher authnEndpointsMatcher = Saml2IdpConfigurerUtils.getAuthnEndpointsRequestMatcher(httpSecurity);

    final List<RequestMatcher> requestMatchers = new ArrayList<>();
    requestMatchers.add(authnEndpointsMatcher);

    this.configurers.values().forEach(configurer -> {
      configurer.init(httpSecurity);
      final RequestMatcher rm = configurer.getRequestMatcher();
      if (rm != null) {
        requestMatchers.add(rm);
      }
    });
    this.endpointsMatcher = new OrRequestMatcher(requestMatchers);
  }

  /** {@inheritDoc} */
  @Override
  public void configure(final HttpSecurity httpSecurity) {

    final IdentityProviderSettings identityProviderSettings =
        Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);

    // Add context filter ...
    //
    final Saml2IdpContextFilter contextFilter = new Saml2IdpContextFilter(identityProviderSettings);
    httpSecurity.addFilterAfter(this.postProcess(contextFilter), SecurityContextHolderFilter.class);

    // Add error response handling filter ...
    //
    final Saml2ResponseBuilder responseBuilder = Saml2IdpConfigurerUtils.getResponseBuilder(httpSecurity);
    final Saml2ResponseSender responseSender = Saml2IdpConfigurerUtils.getResponseSender(httpSecurity);

    final Saml2ErrorResponseProcessingFilter errorResponsefilter =
        new Saml2ErrorResponseProcessingFilter(this.getEndpointsMatcher(), responseBuilder, responseSender,
            Saml2IdpConfigurerUtils.getEventPublisher(httpSecurity));

    httpSecurity.addFilterAfter(this.postProcess(errorResponsefilter), ExceptionTranslationFilter.class);

    // Invoke all the configurers ...
    //
    this.configurers.values().forEach(configurer -> configurer.configure(httpSecurity));
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
    configurers.put(Saml2AuthnRequestProcessorConfigurer.class,
        new Saml2AuthnRequestProcessorConfigurer(this::postProcess));
    configurers.put(Saml2UserAuthenticationConfigurer.class, new Saml2UserAuthenticationConfigurer(this::postProcess));
    return configurers;
  }

  /**
   * Gets a configurer of a given type.
   *
   * @param <T> the class
   * @param type the type
   * @return the configurer or {@code null}
   */
  private <T> T getConfigurer(final Class<T> type) {
    return (T) this.configurers.get(type);
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
    if (!StringUtils.hasText(identityProviderSettings.getBaseUrl())) {
      throw new IllegalArgumentException("Identity Provider base URL must be assigned");
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
    if (!identityProviderSettings.getEndpoints().getRedirectAuthnEndpoint().startsWith("/")) {
      throw new IllegalArgumentException("Invalid endpoint - authn redirect path must begin with /");
    }
    if (!identityProviderSettings.getEndpoints().getPostAuthnEndpoint().startsWith("/")) {
      throw new IllegalArgumentException("Invalid endpoint - authn post path must begin with /");
    }
    if (!identityProviderSettings.getEndpoints().getMetadataEndpoint().startsWith("/")) {
      throw new IllegalArgumentException("Invalid endpoint - metadata path must begin with /");
    }

    // Metadata is optional - If nothing is supplied, the IdP will not expose its metadata.
    if (identityProviderSettings.getMetadata() == null) {
      log.warn("No metadata configuration supplied - the Identity Provider will not expose SAML metadata");
    }

    // Metadata providers
    //
    if (identityProviderSettings.getMetadataProviderConfiguration() != null) {
      final MetadataProviderSettings[] mdConfig = identityProviderSettings.getMetadataProviderConfiguration();
      if (mdConfig == null || mdConfig.length == 0) {
        throw new IllegalArgumentException("No metadata providers have been configured");
      }

      for (int i = 0; i < mdConfig.length; i++) {
        final MetadataProviderSettings md = mdConfig[i];
        if (md.getLocation() == null) {
          throw new IllegalArgumentException("Missing location for metadata provider at position " + i);
        }
        if (md.getLocation() instanceof UrlResource) {
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
    else if (identityProviderSettings.getMetadataProvider() == null) {
      throw new IllegalArgumentException("Missing metadata provider configration - "
          + IdentityProviderSettings.IDP_METADATA_PROVIDER + " or "
          + IdentityProviderSettings.IDP_METADATA_PROVIDER_CONFIGURATION + " must be present");
    }
  }

}
