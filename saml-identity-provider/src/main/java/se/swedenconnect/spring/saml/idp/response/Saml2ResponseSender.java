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
package se.swedenconnect.spring.saml.idp.response;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Response;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.EncodingException;
import net.shibboleth.utilities.java.support.codec.HTMLEncoder;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * A class for posting back a SAML {@link Response} to the client (Service Provider).
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2ResponseSender {

  /** The response page POST sender. */
  private ResponsePage responsePage = new DefaultResponsePage();

  /**
   * Directs the user agent to a page that issues a HTML POST containing the SAML response, and optionally, also the
   * {@code RelayState} variable.
   * 
   * @param httpServletRequest the HTTP servlet request
   * @param httpServletResponse the HTTP servlet response
   * @param destinationUrl the destination URL
   * @param response the SAML response
   * @param relayState the {@code RelayState}, may be {@code null}
   * @throws UnrecoverableSaml2IdpException for send errors
   */
  public void send(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse,
      final String destinationUrl, final Response response, final String relayState)
      throws UnrecoverableSaml2IdpException {

    final String encodedResponse = this.encodeResponse(response);
    final String encodedRelayState = HTMLEncoder.encodeForHTMLAttribute(relayState);

    try {
      this.responsePage.sendResponse(httpServletRequest, httpServletResponse,
          destinationUrl, encodedResponse, encodedRelayState);
    }
    catch (final IOException e) {
      log.error("Failed to send SAML Response to {} - {}", destinationUrl, e.getMessage(), e);
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Failed to send Response message",
          e, new UnrecoverableSaml2IdpException.TraceAuthentication(response.getInResponseTo(), null));
    }

  }

  /**
   * Assigns the {@link ResponsePage} to use when posting back the user. The default is {@link DefaultResponsePage}.
   * 
   * @param responsePage the {@link ResponsePage}
   */
  public void setResponsePage(final ResponsePage responsePage) {
    this.responsePage = Objects.requireNonNull(responsePage, "responsePage must not be null");
  }

  /**
   * Encodes the supplied {@link Response} message for being included in a HTML form.
   * 
   * @param samlResponse the response message
   * @return the Base64-encoding of the message
   * @throws UnrecoverableSaml2IdpException for encoding errors
   */
  protected String encodeResponse(final Response samlResponse) throws UnrecoverableSaml2IdpException {
    try {
      final String xml = SerializeSupport.nodeToString(XMLObjectSupport.marshall(samlResponse));
      return Base64Support.encode(xml.getBytes(StandardCharsets.UTF_8), Base64Support.UNCHUNKED);
    }
    catch (final MarshallingException | EncodingException e) {
      log.error("Failed to encode Response message - {} [destination: '{}', id: '{}', in-response-to: {}]",
          e.getMessage(), samlResponse.getDestination(), samlResponse.getID(), samlResponse.getInResponseTo(), e);

      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Failed to encode Response message", e,
          new UnrecoverableSaml2IdpException.TraceAuthentication(samlResponse.getInResponseTo(), null));
    }
  }

}
