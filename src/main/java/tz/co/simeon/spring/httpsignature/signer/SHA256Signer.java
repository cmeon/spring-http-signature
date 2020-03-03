package tz.co.simeon.spring.httpsignature.signer;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import tz.co.simeon.spring.httpsignature.Algorithm;
import tz.co.simeon.spring.httpsignature.HttpSignatureException;

public class SHA256Signer implements Signer {

  private static Algorithm ALGO = Algorithm.RSA_SHA256;

  PrivateKey keyConfig;

  public SHA256Signer(PrivateKey keyConfig) {
    this.keyConfig = keyConfig;
  }

  public byte[] sign(byte[] bytesToSign) {
    try {
      Signature signature = Signature.getInstance(ALGO.getPortableName(), "BC");
      signature.initSign(keyConfig);

      signature.update(bytesToSign);
      return signature.sign();
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException
        | NoSuchProviderException e) {
      throw new HttpSignatureException(e);
    }
  }
}
