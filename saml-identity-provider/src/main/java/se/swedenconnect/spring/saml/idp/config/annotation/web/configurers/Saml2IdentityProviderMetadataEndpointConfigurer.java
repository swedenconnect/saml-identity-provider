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
package se.swedenconnect.spring.saml.idp.config.annotation.web.configurers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.build.IDPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SingleSignOnServiceBuilder;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.metadata.Saml2MetadataBuilder;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2IdentityProviderMetadataEndpointFilter;

/**
 * Configurer for the metadata publishing endpoint.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2IdentityProviderMetadataEndpointConfigurer extends AbstractSaml2Configurer {

  private RequestMatcher requestMatcher;
  private Consumer<Saml2MetadataBuilder> entityDescriptorCustomizer;
  private Saml2MetadataBuilder entityDescriptorBuilder;

  /**
   * Constructor restricted for internal use.
   *
   * @param objectPostProcessor the post processor
   */
  Saml2IdentityProviderMetadataEndpointConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  /**
   * Sets the {@code Consumer} providing access to the {@link Saml2MetadataBuilder} allowing the ability to customize
   * how the published IdP metadata is constructed.
   *
   * @param metadataCustomizer the {@code Consumer} providing access to the {@link Saml2MetadataBuilder}
   * @return the {@link Saml2IdentityProviderMetadataEndpointConfigurer} for further configuration
   */
  public Saml2IdentityProviderMetadataEndpointConfigurer entityDescriptorCustomizer(
      final Consumer<Saml2MetadataBuilder> metadataCustomizer) {
    this.entityDescriptorCustomizer = metadataCustomizer;
    return this;
  }

  /** {@inheritDoc} */
  @Override
  void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    this.requestMatcher = new AntPathRequestMatcher(
        settings.getEndpoints().getMetadataEndpoint(), HttpMethod.GET.name());

    // Build metadata ...
    //
    try {
      if (settings.getMetadata().getTemplate() != null) {
        this.entityDescriptorBuilder = new Saml2MetadataBuilder(settings.getMetadata().getTemplate().getInputStream());
      }
      else {
        this.entityDescriptorBuilder = new Saml2MetadataBuilder();
      }
      this.entityDescriptorBuilder.entityID(settings.getEntityId());
      this.entityDescriptorBuilder.cacheDuration(settings.getMetadata().getCacheDuration());

      final IDPSSODescriptorBuilder descBuilder = IDPSSODescriptorBuilder.builder();
      descBuilder.wantAuthnRequestsSigned(settings.getRequiresSignedRequests());

      final List<KeyDescriptor> keyDescriptors = new ArrayList<>();
      boolean signAssigned = false;
      boolean encryptAssigned = false;
      if (settings.getCredentials().getSignCredential() != null) {
        signAssigned = true;
        keyDescriptors.add(
            KeyDescriptorBuilder.builder()
                .use(UsageType.SIGNING)
                .certificate(settings.getCredentials().getSignCredential().getCertificate())
                .keyName(settings.getCredentials().getSignCredential().getName())
                .build());
      }
      if (settings.getCredentials().getFutureSignCertificate() != null) {
        keyDescriptors.add(
            KeyDescriptorBuilder.builder()
                .use(UsageType.SIGNING)
                .certificate(settings.getCredentials().getFutureSignCertificate())
                .build());
      }
      if (settings.getCredentials().getEncryptCredential() != null) {
        encryptAssigned = true;
        keyDescriptors.add(
            KeyDescriptorBuilder.builder()
                .use(UsageType.ENCRYPTION)
                .certificate(settings.getCredentials().getEncryptCredential().getCertificate())
                .keyName(settings.getCredentials().getEncryptCredential().getName())
                .build());
        // TODO: encryption methods
      }
      if (settings.getCredentials().getDefaultCredential() != null && (!signAssigned || !encryptAssigned)) {
        final UsageType usage =
            signAssigned ? UsageType.ENCRYPTION : encryptAssigned ? UsageType.SIGNING : UsageType.UNSPECIFIED;
        keyDescriptors.add(
            KeyDescriptorBuilder.builder()
                .use(usage)
                .certificate(settings.getCredentials().getDefaultCredential().getCertificate())
                .keyName(settings.getCredentials().getDefaultCredential().getName())
                .build());
      }
      descBuilder.keyDescriptors(keyDescriptors);

      final List<SingleSignOnService> ssoServices = new ArrayList<>();
      ssoServices.add(SingleSignOnServiceBuilder.builder()
          .redirectBinding()
          .location(settings.getBaseUrl() + settings.getEndpoints().getRedirectAuthnEndpoint())
          .build());
      ssoServices.add(SingleSignOnServiceBuilder.builder()
          .postBinding()
          .location(settings.getBaseUrl() + settings.getEndpoints().getPostAuthnEndpoint())
          .build());

      // Optional Holder-of-key support
      //
      if (settings.getEndpoints().getHokRedirectAuthnEndpoint() != null) {
        ssoServices.add(SingleSignOnServiceBuilder.builder()
            .hokRedirectBinding()
            .location((settings.getHokBaseUrl() != null ? settings.getHokBaseUrl() : settings.getBaseUrl())
                + settings.getEndpoints().getHokRedirectAuthnEndpoint())
            .build());
      }
      if (settings.getEndpoints().getHokPostAuthnEndpoint() != null) {
        ssoServices.add(SingleSignOnServiceBuilder.builder()
            .hokPostBinding()
            .location((settings.getHokBaseUrl() != null ? settings.getHokBaseUrl() : settings.getBaseUrl())
                + settings.getEndpoints().getHokPostAuthnEndpoint())
            .build());
      }

      descBuilder.singleSignOnServices(ssoServices);

      this.entityDescriptorBuilder.ssoDescriptor(descBuilder.build());
    }
    catch (final IOException | XMLParserException | UnmarshallingException e) {
      throw new IllegalArgumentException("Failed to construct IdP metadata - " + e.getMessage(), e);
    }
  }

  /** {@inheritDoc} */
  @Override
  void configure(final HttpSecurity httpSecurity) {

    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);

    if (this.entityDescriptorCustomizer != null) {
      this.entityDescriptorCustomizer.accept(this.entityDescriptorBuilder);
    }

    final X509Credential metadataSigning;
    if (settings.getCredentials().getMetadataSignCredential() != null) {
      metadataSigning = new OpenSamlCredential(settings.getCredentials().getMetadataSignCredential());
    }
    else if (settings.getCredentials().getDefaultCredential() != null) {
      metadataSigning = new OpenSamlCredential(settings.getCredentials().getDefaultCredential());
    }
    else {
      log.warn("No metadata signing credential configured - IdP metadata will not be signed");
      metadataSigning = null;
    }
    final EntityDescriptorContainer container =
        new EntityDescriptorContainer(this.entityDescriptorBuilder.build(), metadataSigning);
    container.setValidity(settings.getMetadata().getValidityPeriod());

    final Saml2IdentityProviderMetadataEndpointFilter filter =
        new Saml2IdentityProviderMetadataEndpointFilter(container, this.requestMatcher);
    httpSecurity.addFilterBefore(postProcess(filter), AbstractPreAuthenticatedProcessingFilter.class);
  }

  /** {@inheritDoc} */
  @Override
  RequestMatcher getRequestMatcher() {
    return this.requestMatcher;
  }

}
