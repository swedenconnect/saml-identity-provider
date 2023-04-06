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
package se.swedenconnect.spring.saml.idp.error;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Base class for unrecoverable SAML errors, i.e., such errors that can not be signalled back to the SAML SP.
 * 
 * @author Martin Lindström
 */
public class UnrecoverableSaml2IdpException extends RuntimeException {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The error. */
  private UnrecoverableSaml2IdpError error;

  /**
   * Constructor.
   * 
   * @param error the error
   */  
  public UnrecoverableSaml2IdpException(final UnrecoverableSaml2IdpError error) {
    this(error, null, null);
  }

  /**
   * Constructor.
   * 
   * @param error the error
   * @param msg the message
   */  
  public UnrecoverableSaml2IdpException(final UnrecoverableSaml2IdpError error, final String msg) {
    this(error, msg, null);
  }

  /**
   * Constructor.
   * 
   * @param error the error
   * @param cause the cause of the error
   */  
  public UnrecoverableSaml2IdpException(final UnrecoverableSaml2IdpError error, final Throwable cause) {
    this(error, null, cause);
  }

  /**
   * Constructor.
   * 
   * @param error the error
   * @param msg the message
   * @param cause the cause of the error
   */
  public UnrecoverableSaml2IdpException(final UnrecoverableSaml2IdpError error, final String msg,
      final Throwable cause) {
    super(msg != null ? msg : error.getDescription(), cause);
    this.error = error;
  }

  /**
   * Gets the specific error.
   * 
   * @return the error
   */
  public UnrecoverableSaml2IdpError getError() {
    return this.error;
  }

}
