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

import java.util.Objects;
import java.util.Optional;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * A {@link NameIDGeneratorFactory} that implements the requirements regarding {@code NameID}'s put by the
 * <a href="https://docs.swedenconnect.se/technical-framework/">Technical Specifications for the Swedish eID
 * Framework</a>.
 *
 * @author Martin Lindström
 */
public class DefaultNameIDGeneratorFactory implements NameIDGeneratorFactory {

  /** The IdP settings. */
  private final IdentityProviderSettings settings;

  /**
   * The default NameID format to use. If not assigned, {@code urn:oasis:names:tc:SAML:2.0:nameid-format:persistent}
   * will be used.
   */
  private String defaultFormat;

  /**
   * Constructor.
   * 
   * @param settings the IdP settings
   */
  public DefaultNameIDGeneratorFactory(final IdentityProviderSettings settings) {
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
    this.defaultFormat = NameID.PERSISTENT;
  }

  /** {@inheritDoc} */
  @Override
  public NameIDGenerator getNameIDGenerator(final AuthnRequest authnRequest, final EntityDescriptor peerMetadata)
      throws Saml2ErrorStatusException, UnrecoverableSaml2IdpException {

    // Find out if the AuthnRequest puts any NameID requirements ...
    //
    String nameFormat = Optional.ofNullable(authnRequest.getNameIDPolicy())
        .map(NameIDPolicy::getFormat)
        .orElse(null);
    if (nameFormat != null) {
      // Note that we ignore the AllowCreate flag. This is because we define all user ID:s to be known to the IdP.
      //
      return this.createNameIDGenerator(nameFormat, this.settings.getEntityId(),
          Optional.ofNullable(authnRequest.getNameIDPolicy()).map(NameIDPolicy::getSPNameQualifier)
              .orElseGet(() -> peerMetadata.getEntityID()));
    }

    // Else, look up the preferred NameID in the SP metadata ...
    //
    final SPSSODescriptor ssoDescriptor = peerMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    for (final NameIDFormat f : ssoDescriptor.getNameIDFormats()) {
      if (NameID.PERSISTENT.equals(f.getURI()) || NameID.TRANSIENT.equals(f.getURI())) {
        nameFormat = f.getURI();
        break;
      }
    }

    return this.createNameIDGenerator(nameFormat, this.settings.getEntityId(), peerMetadata.getEntityID());
  }

  /**
   * Assigns the default {@code NameID} format to use. If not assigned,
   * {@code urn:oasis:names:tc:SAML:2.0:nameid-format:persistent} will be used.
   * 
   * @param format the {@code NameID} format
   */
  public void setDefaultFormat(final String format) {
    Assert.hasText(format, "format must be set");
    if (!this.isSupported(format)) {
      throw new IllegalArgumentException("Unsupported NameID format assigned - " + format);
    }
    this.defaultFormat = format;
  }

  /**
   * Creates a {@link NameIDGenerator} based on the supplied format.
   * 
   * @param format the requested {@code NameID} format.
   * @param nameQualifier the IdP name qualifier
   * @param spNameQualifier the SP name qualifier
   * @return a {@link NameIDGenerator}
   * @throws Saml2ErrorStatusException if the format is unsupported
   */
  protected NameIDGenerator createNameIDGenerator(final String format, final String nameQualifier,
      final String spNameQualifier) throws Saml2ErrorStatusException {

    final String nameIDFormat = format == null || NameID.UNSPECIFIED.equals(format)
        ? this.defaultFormat
        : format;

    if (NameID.PERSISTENT.equals(nameIDFormat)) {
      return new PersistentNameIDGenerator(nameQualifier, spNameQualifier);
    }
    else if (NameID.TRANSIENT.equals(nameIDFormat)) {
      return new TransientNameIDGenerator(nameQualifier, spNameQualifier);
    }
    else {
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_NAMEID);
    }
  }

  /**
   * Predicate that tells whether the supplied {@code NameID} format is supported.
   * 
   * @param format the format to test
   * @return {@code true} if the format is supported and {@code false} otherwise
   */
  protected boolean isSupported(final String format) {
    return NameID.PERSISTENT.equals(format) || NameID.TRANSIENT.equals(format);
  }

}
