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
 * A holder of the {@link IdentityProviderContext} that associates it with the current thread using a
 * {@code ThreadLocal}.
 *
 * @author Martin Lindström
 */
public final class IdentityProviderContextHolder {

  private static final ThreadLocal<IdentityProviderContext> holder = new ThreadLocal<>();

  // Hidden constructor
  private IdentityProviderContextHolder() {
  }

  /**
   * Returns the {@link IdentityProviderContext} bound to the current thread.
   *
   * @return the context
   */
  public static IdentityProviderContext getContext() {
    return holder.get();
  }

  /**
   * Binds the given {@link IdentityProviderContext} to the current thread.
   *
   * @param context the {@link IdentityProviderContext}
   */
  public static void setContext(final IdentityProviderContext context) {
    if (context == null) {
      resetContext();
    }
    else {
      holder.set(context);
    }
  }

  /**
   * Reset the {@link IdentityProviderContext} bound to the current thread.
   */
  public static void resetContext() {
    holder.remove();
  }

}
