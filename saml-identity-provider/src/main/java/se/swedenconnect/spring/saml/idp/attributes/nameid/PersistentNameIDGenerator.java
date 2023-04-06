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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

import org.opensaml.saml.saml2.core.NameID;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * A {@link NameIDGenerator} for generaring persistent {@code NameID}s.
 * 
 * @author Martin Lindström
 */
public class PersistentNameIDGenerator extends AbstractNameIDGenerator {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The JCE hash-algorithm to use. The default is {@code SHA-256}. */
  private String hashAlgorithm;

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, usually the IdP entityID
   * @param spNameQualifier the SP name qualifier
   */
  public PersistentNameIDGenerator(final String nameQualifier, final String spNameQualifier) {
    super(nameQualifier, spNameQualifier);
    this.hashAlgorithm = "SHA-256";
  }

  /** {@inheritDoc} */
  @Override
  protected String getIdentifier(final Saml2UserAuthentication authentication) {

    final String userId = authentication.getName();
    if (userId == null) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Failed to compute NameID - missing user ID");
    }

    try {
      final MessageDigest md = MessageDigest.getInstance(this.hashAlgorithm);
      if (this.getSpNameQualifier() != null) {
        md.update(this.getSpNameQualifier().getBytes());
        md.update((byte) '!');
      }
      if (this.getNameQualifier() != null) {
        md.update(this.getNameQualifier().getBytes());
        md.update((byte) '!');
      }
      md.update(userId.getBytes());
      return Base64.getEncoder().encodeToString(md.digest());
    }
    catch (final NoSuchAlgorithmException e) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Failed to compute NameID", e);
    }
  }

  /**
   * Returns {@code urn:oasis:names:tc:SAML:2.0:nameid-format:persistent}.
   */
  @Override
  protected String getFormat() {
    return NameID.PERSISTENT;
  }

  /**
   * Assigns the JCE name for the hash algorithm to use. The default is {@code SHA-256}.
   * 
   * @param hashAlgorithm the JCE name for the hash algorithm
   */
  public void setHashAlgorithm(final String hashAlgorithm) {
    this.hashAlgorithm = Objects.requireNonNull(hashAlgorithm, "hashAlgorithm must not be null");
  }

}
