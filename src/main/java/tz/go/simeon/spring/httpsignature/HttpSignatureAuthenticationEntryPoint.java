package tz.go.simeon.spring.httpsignature;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * An {@link AuthenticationEntryPoint} implementation used to commence authentication of protected
 * resource requests using {@link HttpSignatureAuthenticationFilter}.
 * <p>
 * Uses information provided by {@link HttpSignatureException} to set HTTP response status code and
 * populate {@code WWW-Authenticate} HTTP header.
 *
 * @author Simeon Mugisha
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target= "_blank">RFC 6750 Section 3:
 *      The WWW-Authenticate Response Header Field</a>
 */
public final class HttpSignatureAuthenticationEntryPoint implements AuthenticationEntryPoint {

  private String realmName;

  /**
   * Collect error details from the provided parameters and format according to RFC 6750,
   * specifically error, error_description, error_uri, and scope.
   *
   * @param request       that resulted in an <code>AuthenticationException</code>
   * @param response      so that the user agent can begin authentication
   * @param authException that caused the invocation
   */
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {

    HttpStatus status = HttpStatus.UNAUTHORIZED;

    Map<String, String> parameters = new LinkedHashMap<>();

    if (this.realmName != null) {
      parameters.put("realm", this.realmName);
    }

    if (authException instanceof HttpSignatureAuthenticationException) {
      parameters.put("error", "401");
      parameters.put("error_description", authException.getMessage());
      parameters.put("error_uri", request.getRequestURI());
    }

    String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);

    response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
    response.setStatus(status.value());
  }

  /**
   * Set the default realm name to use in the bearer token error response
   *
   * @param realmName the name of the realm
   */
  public final void setRealmName(String realmName) {
    this.realmName = realmName;
  }

  private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
    String wwwAuthenticate = "Signature";
    if (!parameters.isEmpty()) {
      wwwAuthenticate += parameters.entrySet().stream()
          .map(attribute -> attribute.getKey() + "=\"" + attribute.getValue() + "\"")
          .collect(Collectors.joining(", ", " ", ""));
    }

    return wwwAuthenticate;
  }
}
