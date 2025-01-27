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
  private static final SignatureSchemeId SCHEME_ID = new SignatureSchemeId("v1a");
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
  public boolean supports(SignatureSchemeId signatureSchemeId) {
    return SCHEME_ID.equals(signatureSchemeId);
  }

  @Override
  public void verify(String messageId, long timestamp, String payload, Signature signatureToVerify)
      throws WebhookSignatureVerificationException {
    try {
      doVerify(messageId, timestamp, payload, signatureToVerify);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | SignatureException
        | InvalidKeySpecException
        | RuntimeException e) {
      throw new WebhookSignatureVerificationException(e);
    }
  }

  private void doVerify(
      String messageId, long timestamp, String payload, Signature signatureToVerify)
      throws NoSuchAlgorithmException,
          InvalidKeyException,
          SignatureException,
          InvalidKeySpecException,
          WebhookSignatureVerificationException {

    java.security.Signature signature = java.security.Signature.getInstance(ALGORITHM);

    java.security.PublicKey publicKey =
        KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(value, ALGORITHM));

    String signedContent = "%s.%s.%s".formatted(messageId, timestamp, payload);
    signature.initVerify(publicKey);
    signature.update(signedContent.getBytes(StandardCharsets.UTF_8));

    if (signature.verify(signatureToVerify.decode())) {
      return;
    }

    throw new WebhookSignatureVerificationException("%s is not valid".formatted(signatureToVerify));
  }
}
