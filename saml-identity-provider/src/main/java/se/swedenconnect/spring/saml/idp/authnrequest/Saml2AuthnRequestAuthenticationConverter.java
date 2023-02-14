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
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
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
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.utils.OpenSamlUtils;

/**
 * An {@link AuthenticationConverter} responsible of decoding a SAML authentication request and checking that is is
 * correct. It will produce an {@link Saml2AuthnRequestAuthenticationToken}.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2AuthnRequestAuthenticationConverter implements AuthenticationConverter {

  /** A decoder for messages sent using the redirect binding. */
  private final HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder;

  /** A decoder for messages sent using the POST binding. */
  private final HTTPPostDecoder httpPostDecoder;

  /**
   * Message handler which checks the validity of the SAML protocol message receiver endpoint against requirements
   * indicated in the message.
   */
  private ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler;

  /** Resolves peer metadata entries. */
  private final MetadataResolver metadataResolver;

  /**
   * Constructor.
   * 
   * @param metadataResolver the metadata resolver that we use when finding SP metadata
   */
  public Saml2AuthnRequestAuthenticationConverter(final MetadataResolver metadataResolver) {
    this.metadataResolver = Objects.requireNonNull(metadataResolver, "metadataResolver must not be null");

    // Initialize the decoders
    //
    try {
      final BindingDescriptor redirectBindingDescriptor = new BindingDescriptor();
      redirectBindingDescriptor.setId(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
      redirectBindingDescriptor.setShortName("Redirect");
      redirectBindingDescriptor.setSignatureCapable(true);
      redirectBindingDescriptor.initialize();
      this.httpRedirectDeflateDecoder = new HTTPRedirectDeflateDecoder();
      this.httpRedirectDeflateDecoder.setBindingDescriptor(redirectBindingDescriptor);
      this.httpRedirectDeflateDecoder.setHttpServletRequestSupplier(OpenSamlUtils.getHttpServletRequestSupplier());
      this.httpRedirectDeflateDecoder.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
      this.httpRedirectDeflateDecoder.initialize();

      final BindingDescriptor postBindingDescriptor = new BindingDescriptor();
      postBindingDescriptor.setId(SAMLConstants.SAML2_POST_BINDING_URI);
      postBindingDescriptor.setShortName("POST");
      postBindingDescriptor.initialize();
      this.httpPostDecoder = new HTTPPostDecoder();
      this.httpPostDecoder.setBindingDescriptor(postBindingDescriptor);
      this.httpPostDecoder.setHttpServletRequestSupplier(OpenSamlUtils.getHttpServletRequestSupplier());
      this.httpPostDecoder.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
      this.httpPostDecoder.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize OpenSAML message decoders", e);
    }

    // Initialize the endpoint security handler.
    //
    this.receivedEndpointSecurityHandler = new ReceivedEndpointSecurityHandler();
    this.receivedEndpointSecurityHandler.setHttpServletRequestSupplier(OpenSamlUtils.getHttpServletRequestSupplier());
    try {
      this.receivedEndpointSecurityHandler.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize endpoint security handler");
    }

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
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_AUTHNREQUEST_FORMAT,
            "Incoming request is not an SAML V2 AuthnRequest message");
      }
      log.debug("AuthnRequest successfully decoded");
      final AuthnRequest authnRequest = AuthnRequest.class.cast(msgContext.getMessage());
      final String relayState = SAMLBindingSupport.getRelayState(msgContext);

      final Saml2AuthnRequestAuthenticationToken token =
          new Saml2AuthnRequestAuthenticationToken(authnRequest, relayState);

      // Save the context for later actions ...
      //
      token.setMessageContext(msgContext);
      final SAMLProtocolContext protocolContext = new SAMLProtocolContext();
      protocolContext.setProtocol(org.opensaml.saml.common.xml.SAMLConstants.SAML20P_NS);
      msgContext.addSubcontext(protocolContext);

      // Check version ...
      //
      final SAMLVersion version = authnRequest.getVersion();
      if (version.getMajorVersion() != 2) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_AUTHNREQUEST_FORMAT,
            "Unsupported version on AuthnRequest message");
      }

      // An ID is mandatory ...
      //
      if (!StringUtils.hasText(authnRequest.getID())) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_AUTHNREQUEST_FORMAT,
            "Missing ID on received AuthnRequest message");
      }

      // Assert that we have the issuer ...
      //
      final String peerEntityId = Optional.ofNullable(authnRequest.getIssuer())
          .map(Issuer::getValue)
          .orElseThrow(() -> new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_AUTHNREQUEST_FORMAT,
              "Missing issuer of received AuthnRequest message"));

      // Check the validity of the SAML protocol message receiver endpoint against requirements
      // indicated in the message.
      //
      this.receivedEndpointSecurityHandler.invoke(msgContext);

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
          throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_AUTHNREQUEST_FORMAT, msg);
        }
        log.debug("SAML metadata for SP {} successfully found", peerEntityId);
        token.setPeerMetadata(spMetadata);

        // Add a context for future OpenSAML operations ...
        //
        final SAMLPeerEntityContext peerContext = new SAMLPeerEntityContext();
        peerContext.setEntityId(spMetadata.getEntityID());
        peerContext.setAuthenticated(false);
        peerContext.setRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        msgContext.addSubcontext(peerContext);

        final SAMLMetadataContext mdContext = new SAMLMetadataContext();
        mdContext.setEntityDescriptor(spMetadata);
        mdContext.setRoleDescriptor(spMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
        msgContext.addSubcontext(mdContext);
      }
      catch (final ResolverException e) {
        final String msg = "Error during metadata lookup: " + e.getMessage();
        log.info("{}", msg, e);
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_AUTHNREQUEST_FORMAT, msg, e);
      }

      return token;
    }
    catch (final MessageDecodingException e) {
      final String msg = "Unable to decode incoming authentication request";
      log.error("{}", msg, e);
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.FAILED_DECODE, msg, e);
    }
    catch (final MessageHandlerException e) {
      final String msg = String.format("Receiver endpoint check failed: %s", e.getMessage());
      log.error("{}", msg, e);
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.ENDPOINT_CHECK_FAILURE, msg, e);
    }
  }

  /**
   * Gets a decoder bean suitable for the given binding.
   *
   * @return a SAMLMessageDecoder bean
   */
  protected SAMLMessageDecoder getDecoder(final HttpServletRequest request) {
    final String method = request.getMethod();
    if ("GET".equals(method)) {
      return this.httpRedirectDeflateDecoder;
    }
    else if ("POST".equals(method)) {
      return this.httpPostDecoder;
    }
    else {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Illegal HTTP verb - " + method);
    }
  }

}
