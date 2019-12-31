package tz.go.simeon.spring.httpsignature;

import lombok.NonNull;

public interface HttpSignatureAuthenticationService {
  public InboundClientConfig loadByKeyId(@NonNull String keyId);
}
