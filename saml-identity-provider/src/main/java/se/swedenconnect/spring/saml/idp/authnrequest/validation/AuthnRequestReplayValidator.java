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

import java.util.Objects;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.response.replay.InMemoryReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayException;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * A {@link AuthnRequestValidator} for protecting against message replay attacks.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class AuthnRequestReplayValidator implements AuthnRequestValidator {

  /** The message replay checker. */
  private final MessageReplayChecker replayChecker;

  /**
   * Default constructor instantiating an in-memory {@link MessageReplayChecker}.
   * <p>
   * Note: This is <b>not</b> recommended in a production environment.
   * </p>
   */
  public AuthnRequestReplayValidator() {
    this(new InMemoryReplayChecker());
  }

  /**
   * Constructor taking the {@link MessageReplayChecker} to use.
   * 
   * @param replayChecker the message replay checker
   */
  public AuthnRequestReplayValidator(final MessageReplayChecker replayChecker) {
    this.replayChecker = Objects.requireNonNull(replayChecker, "replayChecker must not be null");
    if (this.replayChecker instanceof InMemoryReplayChecker) {
      log.warn("{} instantiated with an in-memory replay message checker - DO NOT USE IN PRODUCTION",
          this.getClass().getSimpleName());
    }
  }

  /** {@inheritDoc} */
  @Override
  public void validate(final Saml2AuthnRequestAuthenticationToken authnRequestToken)
      throws UnrecoverableSaml2IdpException, Saml2ErrorStatusException {

    try {
      this.replayChecker.checkReplay(authnRequestToken.getAuthnRequest().getID());
      log.debug("Replay check was successful [{}]", authnRequestToken.getLogString());
    }
    catch (final MessageReplayException e) {
      log.info("Replay of AuthnRequest was detected [{}]", authnRequestToken.getLogString());
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.REPLAY_DETECTED, authnRequestToken);
    }

  }

}
