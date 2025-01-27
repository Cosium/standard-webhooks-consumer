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
  private static final SignatureSchemeId SCHEME_ID = new SignatureSchemeId("v1");
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
  public boolean supports(SignatureSchemeId signatureSchemeId) {
    return SCHEME_ID.equals(signatureSchemeId);
  }

  @Override
  public void verify(String messageId, long timestamp, String payload, Signature signatureToVerify)
      throws WebhookSignatureVerificationException {

    try {
      doVerify(messageId, timestamp, payload, signatureToVerify);
    } catch (RuntimeException e) {
      throw new WebhookSignatureVerificationException(e);
    }
  }

  private void doVerify(
      String messageId, long timestamp, String payload, Signature signatureToVerify)
      throws WebhookSignatureVerificationException {
    String expectedBase64EncodedSignatureContent;
    try {
      expectedBase64EncodedSignatureContent = sign(messageId, timestamp, payload);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new WebhookSignatureVerificationException(e);
    }

    if (expectedBase64EncodedSignatureContent.equals(signatureToVerify.base64EncodedValue())) {
      return;
    }

    throw new WebhookSignatureVerificationException("%s is not valid".formatted(signatureToVerify));
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
