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
package se.swedenconnect.spring.saml.idp.attributes.nameid;

import java.util.Base64;
import java.util.UUID;

import org.opensaml.saml.saml2.core.NameID;

import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * A {@link NameIDGenerator} for generaring transient {@code NameID}s.
 * 
 * @author Martin Lindström
 */
public class TransientNameIDGenerator extends AbstractNameIDGenerator {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, usually the IdP entityID
   * @param spNameQualifier the SP name qualifier
   */
  public TransientNameIDGenerator(final String nameQualifier, final String spNameQualifier) {
    super(nameQualifier, spNameQualifier);
  }

  /** {@inheritDoc} */
  @Override
  protected String getIdentifier(final Saml2UserAuthentication authentication) {    
    return Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes());
  }

  /**
   * Returns {@code urn:oasis:names:tc:SAML:2.0:nameid-format:transient}.
   */
  @Override
  protected String getFormat() {
    return NameID.TRANSIENT;
  }

}
