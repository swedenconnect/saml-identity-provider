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
package se.swedenconnect.spring.saml.idp.demo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

/**
 * Illustration of how we can override the default HTML page that is used to post back the user with the SAML response.
 * 
 * @author Martin Lindström
 */
@Controller
public class ResponseController {

  @GetMapping("/custom-post")
  public ModelAndView customPostPage(
      @RequestParam("destination") final String destination,
      @RequestParam("SAMLResponse") final String samlResponse,
      @RequestParam(name = "RelayState", required = false) final String relayState) {

    final ModelAndView mav = new ModelAndView("post-response");
    mav.addObject("action", destination);
    mav.addObject("SAMLResponse", samlResponse);
    if (StringUtils.hasText(relayState)) {
      mav.addObject("RelayState", relayState);
    }

    return mav;
  }

}
