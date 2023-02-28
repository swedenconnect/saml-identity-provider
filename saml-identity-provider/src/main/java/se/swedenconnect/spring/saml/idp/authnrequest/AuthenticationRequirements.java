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
package se.swedenconnect.spring.saml.idp.authnrequest;

import java.io.Serializable;
import java.util.Collection;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;

/**
 * An interface representing the authentication requirements that we deduce from an {@link AuthnRequest} message and the
 * sending service provider's {@link EntityDescriptor}.
 * 
 * @author Martin Lindström
 */
public interface AuthenticationRequirements extends Serializable {

  /**
   * Tells whether "force authentication" has been set, i.e., whether to force user authentication even though a valid
   * user session exists.
   * 
   * @return {@code true} if authentication should be forced, and {@code false} otherwise
   */
  boolean isForceAuthn();

  /**
   * Tells whether we should issue an assertion without requiring the user to authenticate again.
   * 
   * @return {@code true} if passive authentication is required, and {@code false} otherwise
   */
  boolean isPassiveAuthn();

  /**
   * Gets the collection of declared SAML entity categories for the relying party.
   * 
   * @return a collection of URI:s representing declared entity categories
   */
  Collection<String> getEntityCategories();

  /**
   * Gets the attributes requested directly in the authentication request or indirectly from the relying party metadata
   * ({@code AttributeConsumingService} or entity category declarations).
   * <p>
   * Note: Within the Swedish eID Framework the use of declared entity categories is the preferred way of informing the
   * IdP about which attributes a relying party requests, see {@link #getEntityCategories()}.
   * </p>
   * 
   * @return a collection of requested attributes
   */
  Collection<RequestedAttribute> getRequestedAttributes();

  /**
   * Gets a collection of the requested authentication contexts ({@code AuthnContextClassRef}).
   * <p>
   * The returned list is exhaustive, meaning that all possible URI:s are sent. For example if {@code minimum}
   * comparison is declared, the list is filled with all possible URI:s.
   * </p>
   * 
   * @return a collection of URI:s
   */
  Collection<String> getAuthnContextRequirements();

  /**
   * The <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/14_-_Principal_Selection_in_SAML_Authentication_Requests.html">PrincipalSelection</a>
   * extension defined in Sweden Connect technical framework enables a relying party to include one or more attributes
   * in the {@code AuthnRequest} to inform the IdP about the user that is being authenticated. This method returns this
   * information.
   * 
   * @return a (possibly empty) collection of "principal selection" attributes.
   */
  Collection<UserAttribute> getPrincipalSelectionAttributes();

  /**
   * Gets the {@link SignatureMessageExtension} which is the representation of the {@code SignMessage} extension as
   * specified in section 3.1.2 of <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
   * Extension for Federated Central Signing Services</a>.
   * 
   * @return the sign message extension, or {@code null} if not present
   */
  SignatureMessageExtension getSignatureMessageExtension();

}
