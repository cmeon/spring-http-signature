package tz.go.simeon.spring.httpsignature;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;

/**
 * Authenticates requests that contain a
 * <a href="https://tools.ietf.org/id/draft-cavage-http-signatures-11.html"
 * target= "_blank">Http Signature</a>.
 *
 * This filter should be wired with an {@link AuthenticationManager} that can
 * authenticate a {@link HttpSignatureAuthenticationToken}.
 *
 * @author Simeon Mugisha Rwegayura
 * @see <a href="https://tools.ietf.org/id/draft-cavage-http-signatures-11.html"
 *      target="_blank">Signing HTTP Messages</a>
 * @see HttpSignatureAuthenticationProvider
 */
public class HttpSignatureAuthenticationException extends AuthenticationException {

  public HttpSignatureAuthenticationException(String msg) {
    super(msg);
  }

  private static final long serialVersionUID = 1L;

}