package tz.co.simeon.spring.httpsignature;

/**
 * Exception from HTTP signatures provider.
 */
public class HttpSignatureException extends SecurityException {
  private static final long serialVersionUID = 1L;

  HttpSignatureException(String message) {
    super(message);
  }

  HttpSignatureException(Exception e) {
    super(e);
  }
}
