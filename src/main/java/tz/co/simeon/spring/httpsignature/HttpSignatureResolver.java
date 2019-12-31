package tz.co.simeon.spring.httpsignature;

import javax.servlet.http.HttpServletRequest;

/**
 * A strategy for resolving
 * <a href="https://tools.ietf.org/id/draft-cavage-http-signatures-11.html" target="_blank">Http
 * Signatures</a>s from the {@link HttpServletRequest}.
 *
 * @author Simeon Mugisha Rwegayura
 */
public interface HttpSignatureResolver {

  /**
   * Resolve any
   * <a href="https://tools.ietf.org/id/draft-cavage-http-signatures-11.html" target="_blank">Http
   * Signatures</a> value from the request.
   *
   * @param request the request
   * @return the Http Signatures value or {@code null} if none found
   * @throws HttpSignatureAuthenticationException if the found token is invalid
   */
  HttpSignature resolve(HttpServletRequest request);
}
