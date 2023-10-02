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

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.x509.X509Credential;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.xml.XMLParserException;
import se.swedenconnect.opensaml.saml2.request.AbstractAuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * Test cases for Saml2AuthnRequestAuthenticationConverter.
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestAuthenticationConverterTest extends OpenSamlTestBase {

  private static final String SP = "https://qa.test.swedenconnect.se/sp";

  private static final String IDP = "http://qa.test.swedenconnect.se/idp";

  private static final String RELAY_STATE = "the-relay-state";

  private static final String REDIRECT_RECEIVE_URL = "https://qa.test.swedenconnect.se/idp/profile/SAML2/Redirect/SSO";

  private static final String POST_RECEIVE_URL = "https://qa.test.swedenconnect.se/idp/profile/SAML2/POST/SSO";

  private static EntityDescriptor spMetadata;

  private static EntityDescriptor idpMetadata;

  private MockedStatic<RequestContextHolder> rcHolder;

  @BeforeAll
  public static void init() {
    try {
      spMetadata = unmarshall((new ClassPathResource("sp-metadata.xml")).getInputStream(), EntityDescriptor.class);
      idpMetadata = unmarshall((new ClassPathResource("idp-metadata.xml")).getInputStream(), EntityDescriptor.class);
    }
    catch (XMLParserException | UnmarshallingException | IOException e) {
      throw new SecurityException(e);
    }
  }

  @BeforeEach
  public void setupStaticMock() {
    this.rcHolder = Mockito.mockStatic(RequestContextHolder.class);
  }

  @AfterEach
  public void closeStaticMock() {
    if (rcHolder != null) {
      this.rcHolder.close();
    }
  }

  @Test
  public void testRedirect() throws Exception {

    final RequestHttpObject<AuthnRequest> authnRequest =
        this.getSamlRequest(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

    final UriComponents uriComponents = UriComponentsBuilder.fromUriString(authnRequest.getSendUrl()).build();
    final MultiValueMap<String, String> parameters = uriComponents.getQueryParams();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getContentType()).thenReturn("application/xml");

    Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(REDIRECT_RECEIVE_URL));

    for (final String p : parameters.keySet()) {
      String value = parameters.getFirst(p);
      if (value != null) {
        value = URLDecoder.decode(value, StandardCharsets.UTF_8);
      }
      Mockito.when(request.getParameter(Mockito.matches(p))).thenReturn(value);
    }

    final ServletRequestAttributes servletRequestAttributes = Mockito.mock(ServletRequestAttributes.class);
    Mockito.when(servletRequestAttributes.getRequest()).thenReturn(request);

    rcHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(servletRequestAttributes);

    final MetadataResolver metadataResolver = Mockito.mock(MetadataResolver.class);
    Mockito.when(metadataResolver.resolveSingle(Mockito.any())).thenReturn(spMetadata);

    final IdentityProviderSettings settings = IdentityProviderSettings.builder().build();

    final Saml2AuthnRequestAuthenticationConverter converter =
        new Saml2AuthnRequestAuthenticationConverter(metadataResolver, settings);

    final Authentication a = converter.convert(request);

    Assertions.assertTrue(a instanceof Saml2AuthnRequestAuthenticationToken);
    final Saml2AuthnRequestAuthenticationToken token = (Saml2AuthnRequestAuthenticationToken) a;
    Assertions.assertNotNull(token.getAuthnRequest());
    Assertions.assertNotNull(token.getPeerMetadata());
    Assertions.assertEquals(RELAY_STATE, token.getRelayState());
    Assertions.assertNotNull(token.getMessageContext());

    Assertions.assertEquals(spMetadata.getEntityID(), token.getPrincipal());
    Assertions.assertEquals(spMetadata.getEntityID(), token.getEntityId());
    Assertions.assertEquals(SAMLConstants.SAML2_REDIRECT_BINDING_URI, token.getBindingUri());

    Assertions.assertEquals(String.format("entity-id: '%s', authn-request: '%s'",
        spMetadata.getEntityID(), authnRequest.getRequest().getID()),
        token.getLogString());
  }

  @Test
  public void testPost() throws Exception {

    final RequestHttpObject<AuthnRequest> authnRequest =
        this.getSamlRequest(SAMLConstants.SAML2_POST_BINDING_URI);

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getContentType()).thenReturn("application/xml");

    Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(POST_RECEIVE_URL));

    for (final Map.Entry<String, String> e : authnRequest.getRequestParameters().entrySet()) {
      Mockito.when(request.getParameter(Mockito.matches(e.getKey()))).thenReturn(e.getValue());
    }

    final ServletRequestAttributes servletRequestAttributes = Mockito.mock(ServletRequestAttributes.class);
    Mockito.when(servletRequestAttributes.getRequest()).thenReturn(request);

    rcHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(servletRequestAttributes);

    final MetadataResolver metadataResolver = Mockito.mock(MetadataResolver.class);
    Mockito.when(metadataResolver.resolveSingle(Mockito.any())).thenReturn(spMetadata);

    final IdentityProviderSettings settings = IdentityProviderSettings.builder().build();

    final Saml2AuthnRequestAuthenticationConverter converter =
        new Saml2AuthnRequestAuthenticationConverter(metadataResolver, settings);

    final Authentication a = converter.convert(request);

    Assertions.assertTrue(a instanceof Saml2AuthnRequestAuthenticationToken);
    final Saml2AuthnRequestAuthenticationToken token = (Saml2AuthnRequestAuthenticationToken) a;
    Assertions.assertNotNull(token.getAuthnRequest());
    Assertions.assertNotNull(token.getPeerMetadata());
    Assertions.assertEquals(RELAY_STATE, token.getRelayState());
    Assertions.assertNotNull(token.getMessageContext());

    Assertions.assertEquals(SAMLConstants.SAML2_POST_BINDING_URI, token.getBindingUri());
  }

  @Test
  public void testBadMethod() throws Exception {
    final MetadataResolver metadataResolver = Mockito.mock(MetadataResolver.class);
    final IdentityProviderSettings settings = IdentityProviderSettings.builder().build();

    final Saml2AuthnRequestAuthenticationConverter converter =
        new Saml2AuthnRequestAuthenticationConverter(metadataResolver, settings);

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getMethod()).thenReturn("PUT");

    Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> converter.convert(request));
  }

  @Test
  public void testDecodeError() throws Exception {

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getContentType()).thenReturn("application/xml");

    Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(REDIRECT_RECEIVE_URL));

    Mockito.when(request.getParameter(Mockito.matches("SAMLRequest"))).thenReturn("HJHKDJKHSKJHDKS");

    final ServletRequestAttributes servletRequestAttributes = Mockito.mock(ServletRequestAttributes.class);
    Mockito.when(servletRequestAttributes.getRequest()).thenReturn(request);

    rcHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(servletRequestAttributes);

    final MetadataResolver metadataResolver = Mockito.mock(MetadataResolver.class);
    Mockito.when(metadataResolver.resolveSingle(Mockito.any())).thenReturn(spMetadata);

    final IdentityProviderSettings settings = IdentityProviderSettings.builder().build();

    final Saml2AuthnRequestAuthenticationConverter converter =
        new Saml2AuthnRequestAuthenticationConverter(metadataResolver, settings);

    Assertions.assertEquals(UnrecoverableSaml2IdpError.FAILED_DECODE,
        Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> converter.convert(request))
          .getError());
  }

  @Test
  public void testNoMetadataFound() throws Exception {

    final RequestHttpObject<AuthnRequest> authnRequest =
        this.getSamlRequest(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

    final UriComponents uriComponents = UriComponentsBuilder.fromUriString(authnRequest.getSendUrl()).build();
    final MultiValueMap<String, String> parameters = uriComponents.getQueryParams();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getContentType()).thenReturn("application/xml");

    Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(REDIRECT_RECEIVE_URL));

    for (final String p : parameters.keySet()) {
      String value = parameters.getFirst(p);
      if (value != null) {
        value = URLDecoder.decode(value, StandardCharsets.UTF_8);
      }
      Mockito.when(request.getParameter(Mockito.matches(p))).thenReturn(value);
    }

    final ServletRequestAttributes servletRequestAttributes = Mockito.mock(ServletRequestAttributes.class);
    Mockito.when(servletRequestAttributes.getRequest()).thenReturn(request);

    rcHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(servletRequestAttributes);

    final MetadataResolver metadataResolver = Mockito.mock(MetadataResolver.class);
    Mockito.when(metadataResolver.resolveSingle(Mockito.any())).thenReturn(null);

    final IdentityProviderSettings settings = IdentityProviderSettings.builder().build();

    final Saml2AuthnRequestAuthenticationConverter converter =
        new Saml2AuthnRequestAuthenticationConverter(metadataResolver, settings);

    Assertions.assertEquals(UnrecoverableSaml2IdpError.UNKNOWN_PEER,
        Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> converter.convert(request)).getError());
  }

  @Test
  public void testMetadataError() throws Exception {

    final RequestHttpObject<AuthnRequest> authnRequest =
        this.getSamlRequest(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

    final UriComponents uriComponents = UriComponentsBuilder.fromUriString(authnRequest.getSendUrl()).build();
    final MultiValueMap<String, String> parameters = uriComponents.getQueryParams();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getContentType()).thenReturn("application/xml");

    Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(REDIRECT_RECEIVE_URL));

    for (final String p : parameters.keySet()) {
      String value = parameters.getFirst(p);
      if (value != null) {
        value = URLDecoder.decode(value, StandardCharsets.UTF_8);
      }
      Mockito.when(request.getParameter(Mockito.matches(p))).thenReturn(value);
    }

    final ServletRequestAttributes servletRequestAttributes = Mockito.mock(ServletRequestAttributes.class);
    Mockito.when(servletRequestAttributes.getRequest()).thenReturn(request);

    rcHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(servletRequestAttributes);

    final MetadataResolver metadataResolver = Mockito.mock(MetadataResolver.class);
    Mockito.when(metadataResolver.resolveSingle(Mockito.any())).thenThrow(ResolverException.class);

    final IdentityProviderSettings settings = IdentityProviderSettings.builder().build();

    final Saml2AuthnRequestAuthenticationConverter converter =
        new Saml2AuthnRequestAuthenticationConverter(metadataResolver, settings);

    Assertions.assertEquals(UnrecoverableSaml2IdpError.UNKNOWN_PEER,
        Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> converter.convert(request)).getError());
  }

  @Test
  public void testBadUrl() throws Exception {

    final RequestHttpObject<AuthnRequest> authnRequest =
        this.getSamlRequest(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

    final UriComponents uriComponents = UriComponentsBuilder.fromUriString(authnRequest.getSendUrl()).build();
    final MultiValueMap<String, String> parameters = uriComponents.getQueryParams();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getContentType()).thenReturn("application/xml");

    Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer("https://other.url.com"));

    for (final String p : parameters.keySet()) {
      String value = parameters.getFirst(p);
      if (value != null) {
        value = URLDecoder.decode(value, StandardCharsets.UTF_8);
      }
      Mockito.when(request.getParameter(Mockito.matches(p))).thenReturn(value);
    }

    final ServletRequestAttributes servletRequestAttributes = Mockito.mock(ServletRequestAttributes.class);
    Mockito.when(servletRequestAttributes.getRequest()).thenReturn(request);

    rcHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(servletRequestAttributes);

    final MetadataResolver metadataResolver = Mockito.mock(MetadataResolver.class);
    Mockito.when(metadataResolver.resolveSingle(Mockito.any())).thenReturn(spMetadata);

    final IdentityProviderSettings settings = IdentityProviderSettings.builder().build();

    final Saml2AuthnRequestAuthenticationConverter converter =
        new Saml2AuthnRequestAuthenticationConverter(metadataResolver, settings);

    Assertions.assertEquals(UnrecoverableSaml2IdpError.ENDPOINT_CHECK_FAILURE,
        Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> converter.convert(request)).getError());
  }

  private RequestHttpObject<AuthnRequest> getSamlRequest(final String binding) throws Exception {
    final TestAuthnRequestGenerator generator = new TestAuthnRequestGenerator(null);
    final AuthnRequestGeneratorContext context = new AuthnRequestGeneratorContext() {

      @Override
      public String getPreferredBinding() {
        return binding;
      }
    };
    return generator.generateAuthnRequest(IDP, RELAY_STATE, context);
  }

  private static class TestAuthnRequestGenerator extends AbstractAuthnRequestGenerator {

    public TestAuthnRequestGenerator(final X509Credential signCredential) {
      super(SP, signCredential);
    }

    @Override
    protected EntityDescriptor getSpMetadata() {
      return spMetadata;
    }

    @Override
    protected EntityDescriptor getIdpMetadata(final String idpEntityID) {
      return idpMetadata;
    }

  }

}
