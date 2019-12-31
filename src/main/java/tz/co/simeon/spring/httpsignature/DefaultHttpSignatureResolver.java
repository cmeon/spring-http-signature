package tz.co.simeon.spring.httpsignature;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

public final class DefaultHttpSignatureResolver implements HttpSignatureResolver {

  private static final String SIGNATURE_PREFIX = "signature ";

  /**
   * {@inheritDoc}
   */
  @Override
  public HttpSignature resolve(HttpServletRequest request) {
    HttpSignature signature = resolveFromAuthorizationHeader(request);

    return signature;
  }

  private HttpSignature resolveFromAuthorizationHeader(HttpServletRequest request) {
    Collection<String> authorization =
        Util.values(request, HttpHeaders.AUTHORIZATION).orElse(Collections.emptySet());

    // attempt to validate each authorization, first one that succeeds will finish
    // processing and return
    for (String authorizationValue : authorization) {
      if (authorizationValue.toLowerCase().startsWith(SIGNATURE_PREFIX)) {
        return signatureHeader(
            CollectionsHelper.listOf(authorizationValue.substring(SIGNATURE_PREFIX.length())));
      }
    }
    return null;
  }

  private HttpSignature signatureHeader(List<String> signatures) {
    /*
     * Signature keyId="rsa-key-1",algorithm="rsa-sha256",
     * headers="(request-target) host date digest content-length",
     * signature="Base64(RSA-SHA256(signing string))"
     */
    for (String signature : signatures) {
      HttpSignature httpSignature = HttpSignature.fromHeader(signature);
      Optional<String> validate = httpSignature.validate();
      if (validate.isPresent()) {
        throw new HttpSignatureAuthenticationException(validate.get());
      } else {
        return httpSignature;
      }
    }

    return null;
  }

}
