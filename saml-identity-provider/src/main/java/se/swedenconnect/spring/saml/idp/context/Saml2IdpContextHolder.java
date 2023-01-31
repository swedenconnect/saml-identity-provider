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
package se.swedenconnect.spring.saml.idp.context;

/**
 * A holder of the {@link Saml2IdpContext} that associates it with the current thread using a
 * {@code ThreadLocal}.
 *
 * @author Martin Lindström
 */
public final class Saml2IdpContextHolder {

  private static final ThreadLocal<Saml2IdpContext> holder = new ThreadLocal<>();

  // Hidden constructor
  private Saml2IdpContextHolder() {
  }

  /**
   * Returns the {@link Saml2IdpContext} bound to the current thread.
   *
   * @return the context
   */
  public static Saml2IdpContext getContext() {
    return holder.get();
  }

  /**
   * Binds the given {@link Saml2IdpContext} to the current thread.
   *
   * @param context the {@link Saml2IdpContext}
   */
  public static void setContext(final Saml2IdpContext context) {
    if (context == null) {
      resetContext();
    }
    else {
      holder.set(context);
    }
  }

  /**
   * Reset the {@link Saml2IdpContext} bound to the current thread.
   */
  public static void resetContext() {
    holder.remove();
  }

}
