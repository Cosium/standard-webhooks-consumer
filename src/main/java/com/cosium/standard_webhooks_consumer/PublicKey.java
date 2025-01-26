package com.cosium.standard_webhooks_consumer;

import static java.util.Objects.requireNonNull;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

/**
 * @author Réda Housni Alaoui
 */
class PublicKey implements VerificationKey {

  private static final String SERIALIZATION_PREFIX = "whpk_";
  private static final String SCHEME_ID = "v1a";
  private static final String ALGORITHM = "Ed25519";

  private final byte[] value;

  private PublicKey(byte[] value) {
    this.value = requireNonNull(value);
  }

  public static Optional<PublicKey> parseKey(String serializedVerificationKey) {
    if (!serializedVerificationKey.startsWith(SERIALIZATION_PREFIX)) {
      return Optional.empty();
    }
    return Optional.of(
        new PublicKey(
            Base64.getDecoder()
                .decode(serializedVerificationKey.substring(SERIALIZATION_PREFIX.length()))));
  }

  @Override
  public void verify(String messageId, long timestamp, String payload, Signature signature)
      throws SignatureNotSupportedException, WebhookSignatureVerificationException {
    try {
      doVerify(messageId, timestamp, payload, signature);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | SignatureException
        | InvalidKeySpecException e) {
      throw new WebhookSignatureVerificationException(e);
    }
  }

  private void doVerify(String messageId, long timestamp, String payload, Signature signature)
      throws SignatureNotSupportedException,
          NoSuchAlgorithmException,
          InvalidKeyException,
          SignatureException,
          InvalidKeySpecException {

    if (!SCHEME_ID.equals(signature.schemeId())) {
      throw new SignatureNotSupportedException(
          "%s does not support version <%s>".formatted(this, signature.schemeId()));
    }

    java.security.Signature signatureApi = java.security.Signature.getInstance(ALGORITHM);

    java.security.PublicKey publicKey =
        KeyFactory.getInstance(ALGORITHM)
            .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(value), ALGORITHM));

    String signedContent = "%s.%s.%s".formatted(messageId, timestamp, payload);
    signatureApi.initVerify(publicKey);
    signatureApi.update(signedContent.getBytes(StandardCharsets.UTF_8));

    if (signatureApi.verify(Base64.getDecoder().decode(signature.base64EncodedSignature()))) {
      return;
    }

    throw new SignatureNotSupportedException("The signature is not valid");
  }
}
