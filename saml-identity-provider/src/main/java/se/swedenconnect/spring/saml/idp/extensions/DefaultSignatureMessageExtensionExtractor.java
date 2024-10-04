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

import lombok.extern.slf4j.Slf4j;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.springframework.util.StringUtils;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Default implementation of the {@link SignatureMessageExtensionExtractor} interface.
 *
 * @author Martin Lindström
 */
@Slf4j
public class DefaultSignatureMessageExtensionExtractor implements SignatureMessageExtensionExtractor {

  /** The entityID of the current Identity Provider. */
  private final String entityId;

  /** The SAML object decrypter. */
  private SAMLObjectDecrypter decrypter;

  /**
   * Constructor setting up the object for decrypting {@link SignMessage} objects.
   *
   * @param entityId the IdP entityID
   * @param credentials a list of decryption credentials (if {@code null} decryption will not be supported)
   */
  public DefaultSignatureMessageExtensionExtractor(final String entityId, final List<PkiCredential> credentials) {
    this.entityId = Optional.ofNullable(entityId).filter(StringUtils::hasText)
        .orElseThrow(() -> new IllegalArgumentException("entityId must be assigned"));

    if (credentials != null && !credentials.isEmpty()) {
      final List<Credential> creds = new ArrayList<>();
      credentials.stream().map(OpenSamlCredential::new).forEach(creds::add);
      this.decrypter = new SAMLObjectDecrypter(creds);
      this.decrypter.setPkcs11Workaround(credentials.stream().anyMatch(PkiCredential::isHardwareCredential));
    }
    else {
      log.warn("No encrypt/decrypt credentials available - Encrypted SignMessage elements will not be supported");
    }
  }

  /**
   * Constructor setting up the object for decrypting {@link SignMessage} objects.
   *
   * @param settings IdP settings
   */
  public DefaultSignatureMessageExtensionExtractor(final IdentityProviderSettings settings) {
    this.entityId = settings.getEntityId();

    final List<PkiCredential> decryptionCredentials = new ArrayList<>();
    Optional.ofNullable(settings.getCredentials().getEncryptCredential())
        .ifPresent(decryptionCredentials::add);
    if (decryptionCredentials.isEmpty()) {
      Optional.ofNullable(settings.getCredentials().getDefaultCredential())
          .ifPresent(decryptionCredentials::add);
    }
    if (!decryptionCredentials.isEmpty()) {
      Optional.ofNullable(settings.getCredentials().getPreviousEncryptCredential())
          .ifPresent(decryptionCredentials::add);
    }
    if (decryptionCredentials.isEmpty()) {
      log.warn("No encrypt/decrypt credentials available - Encrypted SignMessage elements will not be supported");
    }
    else {
      final List<Credential> creds = new ArrayList<>();
      decryptionCredentials.stream().map(OpenSamlCredential::new).forEach(creds::add);
      this.decrypter = new SAMLObjectDecrypter(creds);
      this.decrypter.setPkcs11Workaround(decryptionCredentials.stream().anyMatch(PkiCredential::isHardwareCredential));
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignatureMessageExtension extract(final Saml2AuthnRequestAuthenticationToken token)
      throws Saml2ErrorStatusException {

    final SignMessage signMessage = Optional.ofNullable(token.getAuthnRequest().getExtensions())
        .map(e -> e.getUnknownXMLObjects(SignMessage.DEFAULT_ELEMENT_NAME))
        .filter(list -> !list.isEmpty())
        .map(list -> list.get(0))
        .map(SignMessage.class::cast)
        .orElse(null);

    if (signMessage == null) {
      return null;
    }

    // Only Service Providers registered as signature services are allowed to pass along SignMessage
    // extensions. For all other SP:s we simply ignore the extension.
    //
    if (!token.isSignatureServicePeer()) {
      log.info("AuthnRequest contains SignMessage extension, but SP is not a signature service - ignoring [{}]",
          token.getLogString());
      return null;
    }

    if (signMessage.getDisplayEntity() != null && !signMessage.getDisplayEntity().equalsIgnoreCase(this.entityId)) {
      log.info("DisplayEntity of SignMessage ('{}') does not correspond with IdP's entityID - will ignore. [{}]",
          signMessage.getDisplayEntity(), token.getLogString());
      return null;
    }

    final Message clearTextMessage;
    if (signMessage.getEncryptedMessage() != null) {
      try {
        clearTextMessage = this.decrypter.decrypt(signMessage.getEncryptedMessage(), Message.class);
      }
      catch (final DecryptionException e) {
        final String msg = "Failed to decrypt SignMessage";
        log.info("{} - {} [{}]", msg, e.getMessage(), token.getLogString());
        log.debug("", e);
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.SIGN_MESSAGE_DECRYPT, e);
      }
    }
    else {
      clearTextMessage = signMessage.getMessage();
    }

    if (clearTextMessage == null || !StringUtils.hasText(clearTextMessage.getValue())) {
      final String msg = "Invalid SignMessage - missing data to display";
      log.info("{} [{}]", msg, token.getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.SIGN_MESSAGE_DECRYPT, msg);
    }

    return new SignatureMessageExtension(clearTextMessage.getValue(), signMessage.getMimeTypeEnum(),
        signMessage.isMustShow());
  }

}
