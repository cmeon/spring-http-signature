package tz.co.simeon.spring.httpsignature.signer;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import tz.co.simeon.spring.httpsignature.Algorithm;
import tz.co.simeon.spring.httpsignature.HttpSignatureException;

public class SHA256PSSSigner implements Signer {

  private static Algorithm ALGO = Algorithm.RSA_SHA256_PSS;

  private PrivateKey keyConfig;

  public SHA256PSSSigner(PrivateKey keyConfig) {
    this.keyConfig = keyConfig;
  }

  public byte[] sign(byte[] bytesToSign) {
    try {
      Signature signature = Signature.getInstance(ALGO.getPortableName(), "BC");
      signature
          .setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
      signature.initSign(keyConfig);

      signature.update(bytesToSign);
      return signature.sign();
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException
        | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new HttpSignatureException(e);
    }
  }
}
