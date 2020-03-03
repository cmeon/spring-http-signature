package tz.co.simeon.spring.httpsignature;

/**
 * Exception from HTTP signatures provider.
 */
public class HttpSignatureException extends SecurityException {
  private static final long serialVersionUID = 1L;

  public HttpSignatureException(String message) {
    super(message);
  }

  public HttpSignatureException(Exception e) {
    super(e);
  }
}
