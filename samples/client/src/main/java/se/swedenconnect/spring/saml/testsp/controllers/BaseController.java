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
package se.swedenconnect.spring.saml.testsp.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import se.swedenconnect.spring.saml.testsp.config.UiLanguage;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Base controller.
 *
 * @author Martin Lindström
 */
public class BaseController {

  /** Possible languages for the UI. */
  @Autowired
  protected List<UiLanguage> languages;

  /**
   * Updates the MVC model with common attributes such as possible languages.
   *
   * @param model the model
   */
  @ModelAttribute
  public void updateModel(final Model model) {
    final Locale locale = LocaleContextHolder.getLocale();

    model.addAttribute("languages", this.languages.stream()
        .filter(lang -> !lang.getTag().equals(locale.getLanguage()))
        .collect(Collectors.toList()));
  }

}
