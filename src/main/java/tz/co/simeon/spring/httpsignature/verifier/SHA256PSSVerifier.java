package tz.co.simeon.spring.httpsignature.verifier;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Optional;
import tz.co.simeon.spring.httpsignature.Algorithm;

public class SHA256PSSVerifier implements Verifier {

  private static Algorithm ALGO = Algorithm.RSA_SHA256_PSS;
  private byte[] signatureBytes;
  private PublicKey keyConfig;

  public SHA256PSSVerifier(byte[] signatureBytes, PublicKey keyConfig) {
    this.signatureBytes = signatureBytes;
    this.keyConfig = keyConfig;
  }

  public Optional<String> verify(byte[] signedBytes) {
    try {
      Signature signature = Signature.getInstance(ALGO.getPortableName(), "BC");
      signature
          .setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
      signature.initVerify(keyConfig);
      signature.update(signedBytes);

      boolean verified = signature.verify(signatureBytes);
      if (!verified) {
        return Optional.of("Signature is not valid");
      }

      return Optional.empty();
    } catch (NoSuchAlgorithmException e) {
      return Optional.of("SHA256withRSA algorithm not found: " + e.getMessage());
    } catch (InvalidKeyException e) {
      return Optional.of("Invalid RSA key: " + e.getMessage());
    } catch (SignatureException e) {
      return Optional.of("SignatureException: " + e.getMessage());
    } catch (InvalidAlgorithmParameterException e) {
      return Optional.of("Invalid algoritm: " + e.getMessage());
    } catch (NoSuchProviderException e) {
      return Optional.of(
          "Bouncy Castle provider not found: (http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation):"
              + e.getMessage());
    }
  }

}
