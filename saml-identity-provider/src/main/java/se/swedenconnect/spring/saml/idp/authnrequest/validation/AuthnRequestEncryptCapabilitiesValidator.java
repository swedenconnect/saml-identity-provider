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
package se.swedenconnect.spring.saml.idp.authnrequest.validation;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;
import org.opensaml.security.credential.UsageType;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * An {@link AuthnRequestValidator} that asserts that the SP has capabilities to receive an encrypted assertion.
 *
 * @author Martin Lindström
 */
@Slf4j
public class AuthnRequestEncryptCapabilitiesValidator implements AuthnRequestValidator {

  /** Wheter the IdP enctypts assertions. */
  private final boolean encryptedAssertions;

  /**
   * Constructor.
   *
   * @param encryptedAssertions whether assertions are encrypted
   */
  public AuthnRequestEncryptCapabilitiesValidator(final boolean encryptedAssertions) {
    this.encryptedAssertions = encryptedAssertions;
  }

  /** {@inheritDoc} */
  @Override
  public void validate(final Saml2AuthnRequestAuthenticationToken authnRequestToken)
      throws UnrecoverableSaml2IdpException, Saml2ErrorStatusException {

    if (!this.encryptedAssertions) {
      return;
    }

    final SSODescriptor descriptor = EntityDescriptorUtils.getSSODescriptor(authnRequestToken.getPeerMetadata());

    for (final KeyDescriptor kd : descriptor.getKeyDescriptors()) {
      if (UsageType.ENCRYPTION == kd.getUse() || kd.getUse() == null || UsageType.UNSPECIFIED == kd.getUse()) {
        if (kd.getKeyInfo() == null) {
          continue;
        }
        // There is a key info element for encryption ...
        return;
      }
    }
    // If we get here there was no key info suitable for encryption ...
    //
    log.info("SP does not have a KeyDescriptor that can be used for encryption of assertions [{}]",
        authnRequestToken.getLogString());
    throw new Saml2ErrorStatusException(Saml2ErrorStatus.ENCRYPT_NOT_POSSIBLE);
  }

}
