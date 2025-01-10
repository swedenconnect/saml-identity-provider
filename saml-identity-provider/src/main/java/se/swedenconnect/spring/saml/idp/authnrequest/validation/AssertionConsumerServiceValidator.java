/*
 * Copyright 2023-2025 Sweden Connect
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
import net.shibboleth.shared.net.URIComparator;
import net.shibboleth.shared.net.URIException;
import net.shibboleth.shared.net.impl.BasicURLComparator;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

import java.util.Objects;

/**
 * Asserts that the AssertionConsumerService information given in the {@code AuthnRequest} is registered in the SAML
 * metadata. Updates the {@link Saml2AuthnRequestAuthenticationToken} with this information.
 *
 * @author Martin Lindström
 */
@Slf4j
public class AssertionConsumerServiceValidator implements AuthnRequestValidator {

  /** The URI comparator to use in performing URL comparisons. */
  private URIComparator uriComparator = new BasicURLComparator();

  /**
   * Assigns a custom {@link URIComparator}. The default is {@link BasicURLComparator}.
   *
   * @param uriComparator the comparator to use
   */
  public void setUriComparator(final URIComparator uriComparator) {
    this.uriComparator = Objects.requireNonNull(uriComparator, "uriComparator must not be null");
  }

  /**
   * Asserts that the AssertionConsumerService information given in the {@code AuthnRequest} is registered in the SAML
   * metadata. Updates the {@link Saml2AuthnRequestAuthenticationToken} with this information.
   */
  @Override
  public void validate(final Saml2AuthnRequestAuthenticationToken authnRequestToken)
      throws UnrecoverableSaml2IdpException {
    final AuthnRequest authnRequest = authnRequestToken.getAuthnRequest();
    final SPSSODescriptor ssoDesc = authnRequestToken.getPeerMetadata().getSPSSODescriptor(SAMLConstants.SAML20P_NS);

    final String assertionConsumerServiceUrl = authnRequest.getAssertionConsumerServiceURL();
    final Integer assertionConsumerServiceIndex = authnRequest.getAssertionConsumerServiceIndex();

    if (assertionConsumerServiceUrl == null && assertionConsumerServiceIndex == null) {
      log.info("No AssertionConsumerService information provided in AuthnRequest "
          + " - will use default from metadata [{}]", authnRequestToken.getLogString());

      final AssertionConsumerService acs = ssoDesc.getDefaultAssertionConsumerService();
      if (acs == null) {
        final String msg = "No AssertionConsumerService given in AuthnRequest"
            + " and no valid AssertionConsumerService found in metadata";
        log.info("{} [{}]", msg, authnRequestToken.getLogString());
        throw new UnrecoverableSaml2IdpException(
            UnrecoverableSaml2IdpError.INVALID_ASSERTION_CONSUMER_SERVICE, msg, authnRequestToken);
      }

      authnRequestToken.setAssertionConsumerServiceUrl(acs.getLocation());
    }
    for (final AssertionConsumerService acs : ssoDesc.getAssertionConsumerServices()) {
      if (acs.getLocation() == null) {
        continue;
      }
      if (assertionConsumerServiceIndex != null && acs.getIndex() != null
          && assertionConsumerServiceIndex.intValue() == acs.getIndex().intValue()) {
        authnRequestToken.setAssertionConsumerServiceUrl(acs.getLocation());
        break;
      }
      else if (assertionConsumerServiceUrl != null) {
        try {
          if (this.uriComparator.compare(acs.getLocation(), assertionConsumerServiceUrl)) {
            authnRequestToken.setAssertionConsumerServiceUrl(acs.getLocation());
            break;
          }
        }
        catch (final URIException ignored) {
        }
      }
    }
    if (authnRequestToken.getAssertionConsumerServiceUrl() == null) {
      final String msg = "AssertionConsumerService given in AuthnRequest does not appear in metadata";
      log.info("{} [{}]", msg, authnRequestToken.getLogString());
      throw new UnrecoverableSaml2IdpException(
          UnrecoverableSaml2IdpError.INVALID_ASSERTION_CONSUMER_SERVICE, msg, authnRequestToken);
    }

    log.debug("Using AssertionConsumerServiceURL: {} [{}]",
        authnRequestToken.getAssertionConsumerServiceUrl(), authnRequestToken.getLogString());
  }

}
