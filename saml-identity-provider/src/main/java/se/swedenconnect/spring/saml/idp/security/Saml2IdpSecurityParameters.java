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
package se.swedenconnect.spring.saml.idp.security;

import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;

import se.swedenconnect.opensaml.xmlsec.config.SecurityConfiguration;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

public class Saml2IdpSecurityParameters {

  private final IdentityProviderSettings settings;
  private final SecurityConfiguration securityConfiguration;

  public Saml2IdpSecurityParameters(
      final IdentityProviderSettings settings, final SecurityConfiguration securityConfiguration) {
    this.settings = settings;
    this.securityConfiguration = securityConfiguration;
  }

  public SecurityParametersContext getSecurityParametersContext() {

    final SecurityParametersContext context = new SecurityParametersContext();
    final SignatureValidationParameters svp = new SignatureValidationParameters();
    
    return context;
  }

}
