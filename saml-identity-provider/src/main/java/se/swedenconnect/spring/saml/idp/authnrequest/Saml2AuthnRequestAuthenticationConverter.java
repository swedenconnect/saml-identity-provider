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
package se.swedenconnect.spring.saml.idp.authnrequest;

import java.util.Objects;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.binding.BindingDescriptor;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.spring.saml.idp.InternalSaml2IdpException;

/**
 * An {@link AuthenticationConverter} responsible of decoding a SAML authentication request and checking that is is
 * correct.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2AuthnRequestAuthenticationConverter implements AuthenticationConverter {
 
  private final MetadataResolver metadataResolver;
  private BindingDescriptor redirectBindingDescriptor;
  private BindingDescriptor postBindingDescriptor;

  /**
   * Constructor.
   * 
   * @param metadataResolver the metadata resolver that we use when finding SP metadata
   */
  public Saml2AuthnRequestAuthenticationConverter(final MetadataResolver metadataResolver) {
    this.metadataResolver = Objects.requireNonNull(metadataResolver, "metadataResolver must not be null");
    this.initializeBindingDescriptors();
  }

  /** {@inheritDoc} */
  @Override
  public Authentication convert(final HttpServletRequest request) {

    final SAMLMessageDecoder decoder = this.getDecoder(request);
    try {
      decoder.decode();
      final MessageContext msgContext = decoder.getMessageContext();
      log.debug("Incoming request decoded into a message of type {}", msgContext.getMessage().getClass().getName());

      if (!AuthnRequest.class.isInstance(msgContext.getMessage())) {
        throw new InvalidSaml2AuthnRequestException("Incoming request is not an SAML V2 AuthnRequest message");
      }
      log.debug("AuthnRequest successfully decoded");
      final AuthnRequest authnRequest = AuthnRequest.class.cast(msgContext.getMessage());
      final String relayState = SAMLBindingSupport.getRelayState(msgContext);

      final Saml2AuthnRequestAuthenticationToken token =
          new Saml2AuthnRequestAuthenticationToken(authnRequest, relayState);

      // Save the binding context for later actions ...
      token.setSamlBindingContext(msgContext.getSubcontext(SAMLBindingContext.class, false));

      // Check version ...
      //
      final SAMLVersion version = authnRequest.getVersion();
      if (version.getMajorVersion() != 2) {
        throw new InvalidSaml2AuthnRequestException("Unsupported version on AuthnRequest message");
      }

      // Assert that we have the issuer ...
      //
      final String peerEntityId = Optional.ofNullable(authnRequest.getIssuer())
          .map(Issuer::getValue)
          .orElseThrow(() -> new InvalidSaml2AuthnRequestException("Missing issuer of AuthnRequest message"));

      // Check the validity of the SAML protocol message receiver endpoint against requirements
      // indicated in the message.
      //
      this.getReceivedEndpointSecurityHandler(request).invoke(msgContext);

      // Locate peer metadata.
      //
      final CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(peerEntityId),
          new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME),
          new ProtocolCriterion(SAMLConstants.SAML20P_NS));
      try {
        final EntityDescriptor spMetadata = metadataResolver.resolveSingle(criteria);
        if (spMetadata == null) {
          final String msg = String.format("Failed to lookup valid SAML metadata for SP %s", peerEntityId);
          log.info("{}", msg);
          throw new Saml2PeerNotFoundException(msg);
        }
        log.debug("SAML metadata for SP {} successfully found", peerEntityId);
        token.setPeerMetadata(spMetadata);
      }
      catch (final ResolverException e) {
        final String msg = "Error during metadata lookup: " + e.getMessage();
        log.info("{}", msg, e);
        throw new Saml2PeerNotFoundException(msg, e);
      }

      return token;
    }
    catch (final MessageDecodingException e) {
      final String msg = "Unable to decode incoming authentication request";
      log.error("{}", msg, e);
      throw new InvalidSaml2AuthnRequestException(msg, e);
    }
    catch (final MessageHandlerException e) {
      final String msg = String.format("Receiver endpoint check failed: %s", e.getMessage());
      log.error("{}", msg, e);
      throw new InvalidSaml2AuthnRequestException(msg, e);
    }
  }

  /**
   * Gets a decoder bean suitable for the given binding.
   *
   * @return a SAMLMessageDecoder bean
   */
  protected SAMLMessageDecoder getDecoder(final HttpServletRequest request) {
    final String method = request.getMethod();
    final SAMLMessageDecoder messageDecoder;
    if ("GET".equals(method)) {
      final HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
      decoder.setBindingDescriptor(this.redirectBindingDescriptor);
      decoder.setHttpServletRequestSupplier(() -> request);
      decoder.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
      messageDecoder = decoder;
    }
    else if ("POST".equals(method)) {
      HTTPPostDecoder decoder = new HTTPPostDecoder();
      decoder.setBindingDescriptor(this.postBindingDescriptor);
      decoder.setHttpServletRequestSupplier(() -> request);
      decoder.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
      messageDecoder = decoder;
    }
    else {
      throw new InternalSaml2IdpException("Illegal HTTP verb - " + method);
    }
    try {
      messageDecoder.initialize();
      return messageDecoder;
    }
    catch (final ComponentInitializationException e) {
      throw new InternalSaml2IdpException("Failed to initialize message decoder");
    }
  }

  private ReceivedEndpointSecurityHandler getReceivedEndpointSecurityHandler(final HttpServletRequest request) {
    final ReceivedEndpointSecurityHandler handler = new ReceivedEndpointSecurityHandler();
    handler.setHttpServletRequestSupplier(() -> request);
    try {
      handler.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new InternalSaml2IdpException("Failed to initialize endpoint security handler");
    }
    return handler;
  }

  private void initializeBindingDescriptors() {
    try {
      this.redirectBindingDescriptor = new BindingDescriptor();
      this.redirectBindingDescriptor.setId(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
      this.redirectBindingDescriptor.setShortName("Redirect");
      this.redirectBindingDescriptor.setSignatureCapable(true);
      this.redirectBindingDescriptor.initialize();

      this.postBindingDescriptor = new BindingDescriptor();
      this.postBindingDescriptor.setId(SAMLConstants.SAML2_POST_BINDING_URI);
      this.postBindingDescriptor.setShortName("POST");
      this.postBindingDescriptor.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new SecurityException("Failed to initialize OpenSAML BindingDescriptor", e);
    }
  }

}
