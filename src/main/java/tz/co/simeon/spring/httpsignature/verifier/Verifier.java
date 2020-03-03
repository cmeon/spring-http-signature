package tz.co.simeon.spring.httpsignature.verifier;

import java.util.Optional;

public interface Verifier {

  public Optional<String> verify(byte[] signedBytes);

}
