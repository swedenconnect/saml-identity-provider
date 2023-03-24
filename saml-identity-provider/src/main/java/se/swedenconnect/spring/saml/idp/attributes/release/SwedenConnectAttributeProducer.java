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
package se.swedenconnect.spring.saml.idp.attributes.release;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Attribute;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SignMessageDigestIssuer;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;

/**
 * An {@link AttributeProducer} that releases attributes according to the
 * <a href="https://docs.swedenconnect.se/technical-framework/">Technical Specifications for the Swedish eID
 * Framework</a>.
 * <p>
 * The following rules are applied:
 * </p>
 * <ul>
 * <li>All attributes that are explicitly, or implicitly (via entity categories), requested are included (by inheriting
 * from {@link DefaultAttributeProducer}).</li>
 * 
 * <li>The {@code signMessageDigest} attribute if a SignMessage was displayed. See section 3.2.4 of <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/04_-_Attribute_Specification_for_the_Swedish_eID_Framework.html">Attribute
 * Specification for the Swedish eID Framework</a>.</li>
 * </ul>
 * 
 * @author Martin Lindström
 */
@Slf4j
public class SwedenConnectAttributeProducer extends DefaultAttributeProducer {

  /** The helper that calculates the signMessage digest. */
  private SignMessageDigestIssuer signMessageDigestIssuer = new SignMessageDigestIssuer();

  /** {@inheritDoc} */
  @Override
  public List<Attribute> releaseAttributes(final Saml2UserAuthentication userAuthentication) {

    final List<Attribute> attributes = new ArrayList<>(super.releaseAttributes(userAuthentication));

    final Attribute signMessageDigest = this.releaseSignMessageDigest(userAuthentication);
    if (signMessageDigest != null) {
      attributes.add(signMessageDigest);
    }

    return attributes;
  }

  /**
   * Gets the {@code signMessageDigest} attribute or {@code null} if it shouldn't be released.
   * 
   * @param userAuthentication the user authentication token
   * @return the {@code signMessageDigest} attribute or {@code null}
   */
  private Attribute releaseSignMessageDigest(final Saml2UserAuthentication userAuthentication) {
    final SignatureMessageExtension signMessage =
        userAuthentication.getAuthnRequirements().getSignatureMessageExtension();
    if (signMessage == null) {
      return null;
    }
    if (!userAuthentication.getSaml2UserDetails().isSignMessageDisplayed()) {
      return null;
    }

    final Message message = (Message) XMLObjectSupport.buildXMLObject(Message.DEFAULT_ELEMENT_NAME);
    message.setValue(userAuthentication.getAuthnRequirements().getSignatureMessageExtension().getMessage());

    try {
      return this.signMessageDigestIssuer.create(message);
    }
    catch (final Exception e) {
      final String msg = String.format("Failed to construct signMessageDigest - %s", e.getMessage());
      log.info("{} [{}]", msg, userAuthentication.getAuthnRequestToken().getLogString(), e);
      if (signMessage.isMustShow()) {
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.SIGN_MESSAGE, msg);
      }
      else {
        return null;
      }
    }
  }

}
