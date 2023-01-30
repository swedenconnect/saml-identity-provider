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

import org.springframework.security.access.AccessDeniedException;

/**
 * An exception class for reporting errors for SAML peers that are not found (i.e., do not exist in metadata).
 *
 * @author Martin Lindström
 */
public class Saml2PeerNotFoundException extends AccessDeniedException {

  private static final long serialVersionUID = -6661466153961143558L;

  public Saml2PeerNotFoundException(String msg) {
    super(msg);
  }

  public Saml2PeerNotFoundException(String msg, Throwable cause) {
    super(msg, cause);
  }

}
