package tz.go.simeon.spring.httpsignature.pki;

import java.security.PublicKey;

public interface PublicKeyService {
  PublicKey loadPublicKey(String keyId);
}
