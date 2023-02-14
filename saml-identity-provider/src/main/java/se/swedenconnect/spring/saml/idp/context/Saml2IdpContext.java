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
package se.swedenconnect.spring.saml.idp.context;

import se.swedenconnect.spring.saml.idp.response.Saml2ResponseAttributes;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * A context that holds information of the Identity Provider runtime environment.
 *
 * @author Martin Lindström
 */
public interface Saml2IdpContext {

  /**
   * Gets the IdP settings (configuration)
   *
   * @return the IdP settings
   */
  IdentityProviderSettings getSettings();

  /**
   * Gets the {@link Saml2ResponseAttributes}.
   * 
   * @return the attributes needed to send response messages
   */
  Saml2ResponseAttributes getResponseAttributes();

}
