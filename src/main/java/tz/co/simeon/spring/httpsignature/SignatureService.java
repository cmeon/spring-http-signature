package tz.co.simeon.spring.httpsignature;

import tz.co.simeon.spring.httpsignature.signer.Signer;

public class SignatureService {
  OutboundTargetDefinition targetDefinition;

  Algorithm algorithm;

  Signer signer;

  public SignatureService(Algorithm algo) {

  }

  public Signer signer(Algorithm algo) {
    return switch (algo) {
      case RSA_SHA256->  new SHA256Signer(null);
      case RSA_SHA256_PSS->  new SHA256PSSSigner(null);
    }
  }
}
