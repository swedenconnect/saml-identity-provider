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

import java.util.Optional;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.NameID;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * Abstract base class for the {@link NameIDGenerator} interface.
 *
 * @author Martin Lindström
 */
@Slf4j
public abstract class AbstractNameIDGenerator implements NameIDGenerator {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The name qualifier, usually the IdP entityID. */
  private final String nameQualifier;

  /** The SP name qualifier. */
  private final String spNameQualifier;

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, usually the IdP entityID
   * @param spNameQualifier the SP name qualifier
   */
  public AbstractNameIDGenerator(final String nameQualifier, final String spNameQualifier) {
    this.nameQualifier = nameQualifier;
    this.spNameQualifier = spNameQualifier;
  }

  /** {@inheritDoc} */
  @Override
  public NameID getNameID(final Saml2UserAuthentication authentication) {

    final String identifier = this.getIdentifier(authentication);
    final String format = this.getFormat();

    log.debug("Generating NameID '{}' with Format '{}' [{}]", identifier, format,
        Optional.ofNullable(authentication.getAuthnRequestToken())
            .map(Saml2AuthnRequestAuthenticationToken::getLogString).orElseGet(() -> ""));

    final NameID nameID = (NameID) XMLObjectSupport.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
    nameID.setValue(identifier);
    nameID.setFormat(format);
    nameID.setNameQualifier(this.getNameQualifier());
    nameID.setSPNameQualifier(this.getSpNameQualifier());

    return nameID;
  }

  /**
   * Gets the {@code NameID} identifier to use.
   *
   * @param authentication the user authentication object
   * @return an identifier string (never {@code null})
   */
  protected abstract String getIdentifier(final Saml2UserAuthentication authentication);

  /**
   * Gets the {@code Format} for this {@code NameID}.
   *
   * @return the format URI
   */
  protected abstract String getFormat();

  /**
   * Gets the name qualifier, usually the IdP entityID.
   * 
   * @return the name qualifier
   */
  protected String getNameQualifier() {
    return this.nameQualifier;
  }

  /**
   * Gets SP name qualifier.
   * 
   * @return the SP name qualifier
   */
  protected String getSpNameQualifier() {
    return this.spNameQualifier;
  }

}
