package tz.go.simeon.spring.httpsignature;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

/**
 * Authenticates requests that contain a
 * <a href="https://tools.ietf.org/id/draft-cavage-http-signatures-11.html" target= "_blank">Http
 * Signature</a>.
 *
 * This filter should be wired with an {@link AuthenticationManager} that can authenticate a
 * {@link HttpSignatureAuthenticationToken}.
 *
 * @author Simeon Mugisha
 * @see <a href="https://tools.ietf.org/id/draft-cavage-http-signatures-11.html" target=
 *      "_blank">Signing HTTP Messages</a>
 * @see HttpSignatureAuthenticationProvider
 */
@Getter
@Setter
@RequiredArgsConstructor
public class HttpSignatureAuthenticationFilter extends OncePerRequestFilter {
  @NonNull
  private final AuthenticationManager authenticationManager;

  private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
      new WebAuthenticationDetailsSource();

  private HttpSignatureResolver signatureResolver = new DefaultHttpSignatureResolver();

  @NonNull
  private AuthenticationEntryPoint authenticationEntryPoint =
      new HttpSignatureAuthenticationEntryPoint();

  /**
   * Extract any <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target= "_blank">Bearer
   * Token</a> from the request and attempt an authentication.
   *
   * @param request     the http request
   * @param response    the http response
   * @param filterChain the filter chain
   * @throws ServletException thrown when a servlet exception occurs
   * @throws IOException      thrown when there is an IOException
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    final boolean debug = this.logger.isDebugEnabled();

    HttpSignature signature;

    try {
      signature = this.signatureResolver.resolve(request);
    } catch (HttpSignatureAuthenticationException invalid) {
      this.authenticationEntryPoint.commence(request, response, invalid);
      return;
    }

    if (signature == null) {
      filterChain.doFilter(request, response);
      return;
    }

    ResettableStreamHttpServletRequest wrappedRequest =
        new ResettableStreamHttpServletRequest((HttpServletRequest) request);

    HttpSignatureAuthenticationToken authenticationRequest =
        new HttpSignatureAuthenticationToken(signature, wrappedRequest);

    authenticationRequest.setDetails(authenticationDetailsSource.buildDetails(wrappedRequest));

    wrappedRequest.resetInputStream();

    try {
      Authentication authenticationResult =
          authenticationManager.authenticate(authenticationRequest);

      SecurityContext context = SecurityContextHolder.createEmptyContext();
      context.setAuthentication(authenticationResult);
      SecurityContextHolder.setContext(context);

      filterChain.doFilter(wrappedRequest, response);
    } catch (AuthenticationException failed) {
      SecurityContextHolder.clearContext();

      if (debug) {
        this.logger.debug("Authentication request for failed: " + failed);
      }

      this.authenticationEntryPoint.commence(wrappedRequest, response, failed);
    }
  }

}
