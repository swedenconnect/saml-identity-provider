/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.spring.saml.idp.authnrequest;

import java.time.Duration;
import java.time.Instant;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.AbstractMessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.logic.Constraint;

/**
 * Security message handler implementation that checks for validity of SAML message issue instant date and time.
 *
 * Adapted from org.opensaml.saml.common.binding.security.impl.
 */
@Slf4j
public class MessageLifetimeSecurityHandler extends AbstractMessageHandler {

    /**
     * Clock skew adjustment in both directions to consider still acceptable (Default value: 3 minutes).
     */
    @Nonnull private Duration clockSkew;

    /** Amount of time for which a message is valid after it is issued (Default value: 3 minutes). */
    @Nonnull private Duration messageLifetime;

    /** Whether this rule is required to be met. */
    private boolean requiredRule;

    /** Constructor. */
    public MessageLifetimeSecurityHandler() {
        clockSkew = Duration.ofMinutes(3);
        messageLifetime = Duration.ofMinutes(3);
        requiredRule = true;
    }

    /**
     * Get the clock skew.
     *
     * @return the clock skew
     */
    @Nonnull public Duration getClockSkew() {
        return clockSkew;
    }

    /**
     * Set the clock skew.
     *
     * @param skew clock skew to set
     */
    public void setClockSkew(@Nonnull final Duration skew) {
        // checkSetterPreconditions();

        clockSkew = Constraint.isNotNull(skew, "Clock skew cannot be null");
    }

    /**
     * Gets the amount of time for which a message is valid.
     *
     * @return amount of time for which a message is valid
     */
    @Nonnull public Duration getMessageLifetime() {
        return messageLifetime;
    }

    /**
     * Sets the amount of time for which a message is valid.
     *
     * @param lifetime amount of time for which a message is valid
     */
    public synchronized void setMessageLifetime(@Nonnull final Duration lifetime) {
        // checkSetterPreconditions();
        Constraint.isNotNull(lifetime, "Lifetime cannot be null");
        Constraint.isFalse(lifetime.isNegative(), "Lifetime cannot be negative");

        messageLifetime = lifetime;
    }

    /**
     * Gets whether this rule is required to be met.
     *
     * @return whether this rule is required to be met
     */
    public boolean isRequiredRule() {
        return requiredRule;
    }

    /**
     * Sets whether this rule is required to be met.
     *
     * @param required whether this rule is required to be met
     */
    public void setRequiredRule(final boolean required) {
        // checkSetterPreconditions();

        requiredRule = required;
    }

    /** {@inheritDoc} */
    @Override
    public void doInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {
        final SAMLMessageInfoContext msgInfoContext = messageContext.ensureSubcontext(SAMLMessageInfoContext.class);

        final Instant issueInstant = msgInfoContext.getMessageIssueInstant();
        if (issueInstant == null) {
            if (requiredRule) {
                log.warn("{} Inbound SAML message issue instant not present in message context", getLogPrefix());
                throw new MessageHandlerException("Inbound SAML message issue instant not present in message context");
            }
            return;
        }

        final Instant now = Instant.now();
        final Instant latestValid = now.plus(getClockSkew().abs());
        final Instant expiration = issueInstant.plus(getClockSkew().abs()).plus(getMessageLifetime());

        // Check message wasn't issued in the future
        if (issueInstant.isAfter(latestValid)) {
            log.warn("{} Message was not yet valid: message time was {}, latest valid is: {}", getLogPrefix(),
                    issueInstant, latestValid);
            throw new MessageHandlerException("Message was rejected because it was issued in the future");
        }

        // Check message has not expired
        if (expiration.isBefore(now)) {
            log.warn(
                    "{} Message was expired: message time was '{}', message expired at: '{}', current time: '{}'",
                    getLogPrefix(), issueInstant, expiration, now);
            throw new MessageHandlerException("Message was rejected due to issue instant expiration");
        }
    }

}
