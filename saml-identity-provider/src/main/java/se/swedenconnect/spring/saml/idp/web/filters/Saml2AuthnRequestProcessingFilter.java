package se.swedenconnect.spring.saml.idp.web.filters;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2UserAuthenticationInputToken;

/**
 * A {@code Filter} that processes SAML {@code AuthnRequest} messages.
 */
@Slf4j
public class Saml2AuthnRequestProcessingFilter extends OncePerRequestFilter {

  /** The authentication manager. */
  private final AuthenticationManager authenticationManager;

  /** The request matcher for the SSO endpoints. */
  private final RequestMatcher requestMatcher;

  /** The {@link AuthenticationConverter} that builds an {@link Authentication} object from the request. */
  private final AuthenticationConverter authenticationConverter;

  /** The authentication success handler. */
  private AuthenticationSuccessHandler authenticationSuccessHandler = this::onAuthenticationSuccess;

  /**
   * Constructor.
   * 
   * @param authenticationManager the authentication manager
   * @param requestMatcher the request matcher for matching incoming requests
   * @param authenticationConverter the authentication converter that converts a SAML {@code AuthnRequest} message
   */
  public Saml2AuthnRequestProcessingFilter(
      final AuthenticationManager authenticationManager,
      final RequestMatcher requestMatcher,
      final AuthenticationConverter authenticationConverter) {
    this.authenticationManager =
        Objects.requireNonNull(authenticationManager, "authenticationManager must not be null");
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.authenticationConverter =
        Objects.requireNonNull(authenticationConverter, "authenticationConverter must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(
      final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    // Convert the incoming AuthnRequest ...
    //
    final Authentication authnRequest = this.authenticationConverter.convert(request);
    
    if (authnRequest != null && Saml2AuthnRequestAuthenticationToken.class.isInstance(authnRequest)) {
      
      // Check for possible authentication token that may be used for SSO.
      //
      final Authentication userAuthentication = SecurityContextHolder.getContext().getAuthentication();
      if (userAuthentication != null && userAuthentication.isAuthenticated()) {
        Saml2AuthnRequestAuthenticationToken.class.cast(authnRequest).setAuthenticatedUser(userAuthentication);
      }
      
      // Verify the authentication request and produce an input token for user authentication ...
      // Also check for possible SSO ...
      //
      final Authentication token = this.authenticationManager.authenticate(authnRequest);
      if (Saml2UserAuthenticationInputToken.class.isInstance(token)) {
        // The authentication request was verified, but we haven't authenticated the user yet.
        // Save this input token and continue the filter chain ...
        //
        this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, token);        
      }
      else if (Saml2UserAuthentication.class.isInstance(token)) {
        // OK, it seems like we got an authenticated user ...
        //
        this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, token);
      }
    }
    filterChain.doFilter(request, response);
  }

  /**
   * Sets the {@link AuthenticationSuccessHandler} used for handling a successful client authentication and associating
   * the {@link Saml2AuthnRequestAuthenticationToken} to the {@link SecurityContext}.
   *
   * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling a successful client
   *          authentication
   */
  public void setAuthenticationSuccessHandler(final AuthenticationSuccessHandler authenticationSuccessHandler) {
    Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
    this.authenticationSuccessHandler = authenticationSuccessHandler;
  }

  /**
   * Default authentication success handler.
   * 
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param authentication the authentication object
   */
  private void onAuthenticationSuccess(
      final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) {

    final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
    securityContext.setAuthentication(authentication);
    SecurityContextHolder.setContext(securityContext);
    log.debug("Setting SecurityContextHolder authentication to {}", authentication.getClass().getSimpleName());
  }

}
