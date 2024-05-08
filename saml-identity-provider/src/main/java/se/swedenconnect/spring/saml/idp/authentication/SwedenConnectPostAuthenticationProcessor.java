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
package se.swedenconnect.spring.saml.idp.authentication;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;

/**
 * A {@link PostAuthenticationProcessor} that applies the rules of Sweden Connect, see
 * <a href="https://docs.swedenconnect.se/technical-framework/">Technical Specifications for the Swedish eID
 * Framework</a>.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class SwedenConnectPostAuthenticationProcessor implements PostAuthenticationProcessor {

  /**
   * Applies the following checks:
   * <ul>
   * <li>If the request is from a Signature Service and the SignMessage has been flagged with "must show" the method
   * asserts that a sign message has been displayed during authentication.</li>
   * <li>TODO: more ...</li>
   * </ul>
   */
  @Override
  public void process(final Saml2UserAuthentication token) throws Saml2ErrorStatusException {

    final SignatureMessageExtension signMessage = token.getAuthnRequirements().getSignatureMessageExtension();
    if (signMessage != null) {
      if (!token.getSaml2UserDetails().isSignMessageDisplayed() && signMessage.isMustShow()) {
        final String msg = "SignMessage could not be displayed";
        log.info("{} [{}]", msg, token.getAuthnRequestToken().getLogString());
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.SIGN_MESSAGE_NOT_DISPLAYED, msg);
      }
    }
  }
  
}
