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
package se.swedenconnect.spring.saml.idp.authnrequest;

import java.io.Serial;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import lombok.Setter;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.extensions.SadRequestExtension;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;
import se.swedenconnect.spring.saml.idp.extensions.UserMessageExtension;

/**
 * A builder for {@link AuthenticationRequirements}.
 *
 * @author Martin Lindström
 */
public class AuthenticationRequirementsBuilder {

  private final AuthenticationRequirementsImpl reqs;

  /**
   * Default constructor.
   */
  public AuthenticationRequirementsBuilder() {
    this.reqs = new AuthenticationRequirementsImpl();
  }

  /**
   * Constructor setting up a builder based on an existing {@link AuthenticationRequirements} object.
   *
   * @param requirements the template object
   */
  public AuthenticationRequirementsBuilder(final AuthenticationRequirements requirements) {
    this.reqs = requirements != null
        ? new AuthenticationRequirementsImpl(requirements)
        : new AuthenticationRequirementsImpl();
  }

  /**
   * Creates a {@link AuthenticationRequirementsBuilder}.
   *
   * @return a builder
   */
  public static AuthenticationRequirementsBuilder builder() {
    return new AuthenticationRequirementsBuilder();
  }

  /**
   * Creates a {@link AuthenticationRequirementsBuilder} based on an existing {@link AuthenticationRequirements}
   * object.
   *
   * @param requirements the template object
   * @return a builder
   */
  public static AuthenticationRequirementsBuilder builder(final AuthenticationRequirements requirements) {
    return new AuthenticationRequirementsBuilder(requirements);
  }

  /**
   * Builds the {@link AuthenticationRequirements} object
   *
   * @return an {@link AuthenticationRequirements}
   */
  public AuthenticationRequirements build() {
    return this.reqs;
  }

  /**
   * Tells whether "force authentication" has been set, i.e., whether to force user authentication even though a valid
   * user session exists.
   *
   * @param forceAuthn {@code true} if authentication should be forced, and {@code false} otherwise
   * @return the builder
   */
  public AuthenticationRequirementsBuilder forceAuthn(final boolean forceAuthn) {
    this.reqs.setForceAuthn(forceAuthn);
    return this;
  }

  /**
   * Tells whether we should issue an assertion without requiring the user to authenticate again.
   *
   * @param passiveAuthn {@code true} if passive authentication is required, and {@code false} otherwise
   * @return the builder
   */
  public AuthenticationRequirementsBuilder passiveAuthn(final boolean passiveAuthn) {
    this.reqs.setPassiveAuthn(passiveAuthn);
    return this;
  }

  /**
   * Assigns the collection of declared SAML entity categories for the relying party.
   *
   * @param entityCategories a collection of URI:s representing declared entity categories
   * @return the builder
   */
  public AuthenticationRequirementsBuilder entityCategories(final Collection<String> entityCategories) {
    this.reqs.getEntityCategories().clear();
    this.reqs.getEntityCategories().addAll(entityCategories);
    return this;
  }

  /**
   * Adds an entity category.
   *
   * @param entityCategory an entity category URI
   * @return the builder
   */
  public AuthenticationRequirementsBuilder entityCategory(final String entityCategory) {
    this.reqs.getEntityCategories().add(entityCategory);
    return this;
  }

  /**
   * Assigns the attributes requested directly in the authentication request or indirectly from the relying party
   * metadata ({@code AttributeConsumingService} or entity category declarations).
   * <p>
   * Note: Within the Swedish eID Framework the use of declared entity categories is the preferred way of informing the
   * IdP about which attributes a relying party requests, see {@link #entityCategories(Collection)}.
   * </p>
   *
   * @param requestedAttributes a collection of requested attributes
   * @return the builder
   */
  public AuthenticationRequirementsBuilder requestedAttributes(
      final Collection<RequestedAttribute> requestedAttributes) {
    this.reqs.getRequestedAttributes().clear();
    this.reqs.getRequestedAttributes().addAll(requestedAttributes);
    return this;
  }

  /**
   * Adds a requested attribute.
   *
   * @param requestedAttribute the requested attribute
   * @return the builder
   */
  public AuthenticationRequirementsBuilder requestedAttribute(final RequestedAttribute requestedAttribute) {
    this.reqs.getRequestedAttributes().add(requestedAttribute);
    return this;
  }

  /**
   * Assigns a collection of the requested authentication contexts ({@code AuthnContextClassRef}).
   *
   * @param authnContextRequirements a collection of URI:s
   * @return the builder
   */
  public AuthenticationRequirementsBuilder authnContextRequirements(final Collection<String> authnContextRequirements) {
    this.reqs.getAuthnContextRequirements().clear();
    this.reqs.getAuthnContextRequirements().addAll(authnContextRequirements);
    return this;
  }

  /**
   * Adds a requested authentication contexts ({@code AuthnContextClassRef}).
   *
   * @param authnContextRequirement URI
   * @return the builder
   */
  public AuthenticationRequirementsBuilder authnContextRequirement(final String authnContextRequirement) {
    this.reqs.getAuthnContextRequirements().add(authnContextRequirement);
    return this;
  }

  /**
   * The <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/14_-_Principal_Selection_in_SAML_Authentication_Requests.html">PrincipalSelection</a>
   * extension defined in Sweden Connect technical framework enables a relying party to include one or more attributes
   * in the {@code AuthnRequest} to inform the IdP about the user that is being authenticated. This method assigns this
   * information.
   *
   * @param principalSelectionAttributes a collection of "principal selection" attributes
   * @return the builder
   */
  public AuthenticationRequirementsBuilder principalSelectionAttributes(
      final Collection<UserAttribute> principalSelectionAttributes) {
    this.reqs.getPrincipalSelectionAttributes().clear();
    this.reqs.getPrincipalSelectionAttributes().addAll(principalSelectionAttributes);
    return this;
  }

  /**
   * Adds a principal selection attribute.
   *
   * @param principalSelectionAttribute principal selection attribute
   * @return the builder
   */
  public AuthenticationRequirementsBuilder principalSelectionAttribute(
      final UserAttribute principalSelectionAttribute) {
    this.reqs.getPrincipalSelectionAttributes().add(principalSelectionAttribute);
    return this;
  }

  /**
   * Assigns the {@link SignatureMessageExtension} which is the representation of the {@code SignMessage} extension as
   * specified in section 3.1.2 of <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
   * Extension for Federated Central Signing Services</a>.
   *
   * @param signatureMessageExtension the sign message extension
   * @return the builder
   */
  public AuthenticationRequirementsBuilder signatureMessageExtension(
      final SignatureMessageExtension signatureMessageExtension) {
    this.reqs.setSignatureMessageExtension(signatureMessageExtension);
    return this;
  }

  /**
   * Assigns the {@link UserMessageExtension} which is the representation of the {@code UserMessage} extension as
   * specified in <a
   * href="https://docs.swedenconnect.se/technical-framework/updates/18_-_User_Message_Extension_in_SAML_Authentication_Requests.html">User
   * Message Extension in SAML Authentication Requests</a>.
   *
   * @param userMessageExtension the user message extension
   * @return the builder
   */
  public AuthenticationRequirementsBuilder userMessageExtension(final UserMessageExtension userMessageExtension) {
    this.reqs.setUserMessageExtension(userMessageExtension);
    return this;
  }

  /**
   * Assigns the {@link SadRequestExtension} which is the representation of the {@code SADRequest} extension as
   * specified in <a href=
   * "https://docs.swedenconnect.se/technical-framework/updates/13_-_Signature_Activation_Protocol.html">Signature
   * Activation Protocol for Federated Signing</a>.
   *
   * @param sadRequestExtension the extension
   * @return the builder
   */
  public AuthenticationRequirementsBuilder sadRequestExtension(
      final SadRequestExtension sadRequestExtension) {
    this.reqs.setSadRequestExtension(sadRequestExtension);
    return this;
  }

  // Implementation class
  private static class AuthenticationRequirementsImpl implements AuthenticationRequirements {

    @Serial
    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    @Setter
    private boolean forceAuthn = false;

    @Setter
    private boolean passiveAuthn = false;

    private final List<String> entityCategories;

    private final List<RequestedAttribute> requestedAttributes;

    private final List<String> authnContextRequirements;

    private final List<UserAttribute> principalSelectionAttributes;

    @Setter
    private SignatureMessageExtension signatureMessageExtension;

    @Setter
    private UserMessageExtension userMessageExtension;

    @Setter
    private SadRequestExtension sadRequestExtension;

    public AuthenticationRequirementsImpl() {
      this.entityCategories = new ArrayList<>();
      this.requestedAttributes = new ArrayList<>();
      this.authnContextRequirements = new ArrayList<>();
      this.principalSelectionAttributes = new ArrayList<>();
    }

    public AuthenticationRequirementsImpl(final AuthenticationRequirements reqs) {
      this();
      this.forceAuthn = reqs.isForceAuthn();
      this.passiveAuthn = reqs.isPassiveAuthn();
      this.entityCategories.addAll(reqs.getEntityCategories());
      this.requestedAttributes.addAll(reqs.getRequestedAttributes());
      this.authnContextRequirements.addAll(reqs.getAuthnContextRequirements());
      this.principalSelectionAttributes.addAll(reqs.getPrincipalSelectionAttributes());
      this.signatureMessageExtension = reqs.getSignatureMessageExtension();
      this.userMessageExtension = reqs.getUserMessageExtension();
      this.sadRequestExtension = reqs.getSadRequestExtension();
    }

    @Override
    public boolean isForceAuthn() {
      return this.forceAuthn;
    }

    @Override
    public boolean isPassiveAuthn() {
      return this.passiveAuthn;
    }

    // Returns the live list.
    @NonNull
    @Override
    public List<String> getEntityCategories() {
      return this.entityCategories;
    }

    // Returns the live list.
    @NonNull
    @Override
    public Collection<RequestedAttribute> getRequestedAttributes() {
      return this.requestedAttributes;
    }

    // Returns the live list.
    @NonNull
    @Override
    public List<String> getAuthnContextRequirements() {
      return this.authnContextRequirements;
    }

    // Returns the live list.
    @NonNull
    @Override
    public Collection<UserAttribute> getPrincipalSelectionAttributes() {
      return this.principalSelectionAttributes;
    }

    @Nullable
    @Override
    public SignatureMessageExtension getSignatureMessageExtension() {
      return this.signatureMessageExtension;
    }

    @Nullable
    @Override
    public UserMessageExtension getUserMessageExtension() {
      return this.userMessageExtension;
    }

    @Nullable
    @Override
    public SadRequestExtension getSadRequestExtension() {
      return this.sadRequestExtension;
    }

  }
}
