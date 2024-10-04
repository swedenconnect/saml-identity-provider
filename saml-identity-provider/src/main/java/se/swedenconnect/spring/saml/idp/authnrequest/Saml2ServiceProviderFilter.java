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

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import java.util.function.Predicate;

/**
 * A {@link Predicate} that tells whether a SAML Service Provider sending an authentication request is accepted. The
 * predicate will be applied after the request has been fully validated. The primary purpose for the filter is that
 * Identity Providers wishing to restrict its services to only some SP:s within a federation can do so.
 *
 * @author Martin Lindström
 */
public interface Saml2ServiceProviderFilter extends Predicate<EntityDescriptor> {
}
