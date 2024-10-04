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
package se.swedenconnect.spring.saml.idp.extensions;

import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * The contract for extracting, and possibly decrypting, a {@code SignMessage} extension. See
 * {@link SignatureMessageExtension}.
 *
 * @author Martin Lindström
 */
public interface SignatureMessageExtensionExtractor {

  /**
   * Given an authentication request, the method will extract the {@code SignMessage} extension, and if it is encrypted
   * also decrypt it.
   *
   * @param token the authentication request token
   * @return a {@link SignatureMessageExtension} or {@code null} if no {@code SignMessage} is available
   * @throws Saml2ErrorStatusException for decryption errors
   * @throws UnrecoverableSaml2IdpException for unrecoverable errors
   */
  SignatureMessageExtension extract(final Saml2AuthnRequestAuthenticationToken token)
      throws Saml2ErrorStatusException, UnrecoverableSaml2IdpException;

}
