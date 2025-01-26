package com.cosium.standard_webhooks_consumer;

import static java.util.Objects.requireNonNull;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Réda Housni Alaoui
 */
class SecretKey implements VerificationKey {

  private static final String SERIALIZATION_PREFIX = "whsec_";
  private static final String SCHEME_ID = "v1";
  private static final String ALGORITHM = "HmacSHA256";

  private final byte[] value;

  private SecretKey(byte[] value) {
    this.value = requireNonNull(value);
  }

  public static Optional<SecretKey> parseKey(String serializedVerificationKey) {
    if (!serializedVerificationKey.startsWith(SERIALIZATION_PREFIX)) {
      return Optional.empty();
    }
    return Optional.of(
        new SecretKey(
            Base64.getDecoder()
                .decode(serializedVerificationKey.substring(SERIALIZATION_PREFIX.length()))));
  }

  @Override
  public void verify(String messageId, long timestamp, String payload, Signature signature)
      throws SignatureNotSupportedException, WebhookSignatureVerificationException {

    if (!SCHEME_ID.equals(signature.schemeId())) {
      throw new SignatureNotSupportedException(
          "%s does not support version <%s>".formatted(this, signature.schemeId()));
    }

    String expectedBase64EncodedSignatureContent;
    try {
      expectedBase64EncodedSignatureContent = sign(messageId, timestamp, payload);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new WebhookSignatureVerificationException(e);
    }

    if (expectedBase64EncodedSignatureContent.equals(signature.base64EncodedSignature())) {
      return;
    }

    throw new SignatureNotSupportedException(
        "The provided signature does not match the expected signature.");
  }

  private String sign(String messageId, long timestamp, String payload)
      throws NoSuchAlgorithmException, InvalidKeyException {
    String contentToSign = "%s.%s.%s".formatted(messageId, timestamp, payload);
    Mac sha512Hmac = Mac.getInstance(ALGORITHM);
    SecretKeySpec keySpec = new SecretKeySpec(value, ALGORITHM);
    sha512Hmac.init(keySpec);
    byte[] macData = sha512Hmac.doFinal(contentToSign.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(macData);
  }
}
