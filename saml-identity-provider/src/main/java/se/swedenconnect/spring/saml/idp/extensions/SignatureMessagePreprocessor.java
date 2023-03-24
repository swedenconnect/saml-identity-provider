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
package se.swedenconnect.spring.saml.idp.extensions;

import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessageMimeTypeEnum;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * An interface that defines pre-processing of signature messages before they are displayed.
 * <p>
 * Typically an implementation will filter the input to avoid unwanted characters and to protect from XSS attacks and
 * such, and then translate the message into the format that is suitable for the service's UI.
 * </p>
 * 
 * @author Martin Lindström
 */
public interface SignatureMessagePreprocessor {

  /**
   * Applies processing of the supplied message where filtering, validation and transformation to the service's desired
   * display format can be done.
   * 
   * @param encodedMessage the cleartext sign message (in Base64 encoding)
   * @param messageType the mime type
   * @return the filtered (and transformed) message
   * @throws Saml2ErrorStatusException for invalid input
   */
  String processSignMessage(final String encodedMessage, final SignMessageMimeTypeEnum messageType)
      throws Saml2ErrorStatusException;
}
