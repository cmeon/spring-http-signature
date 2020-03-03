package tz.co.simeon.spring.httpsignature.signer;

public interface Signer {

  public byte[] sign(byte[] bytesToSign);

}
