package com.cosium.standard_webhooks_consumer;

import static java.util.Objects.requireNonNull;

import java.net.http.HttpHeaders;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Réda Housni Alaoui
 */
public class WebhookSignatureVerifier {

  private static final Logger LOGGER = LoggerFactory.getLogger(WebhookSignatureVerifier.class);

  private static final CompositeVerificationKeyParser VERIFICATION_KEY_PARSER =
      new CompositeVerificationKeyParser(SecretKey::parseKey, PublicKey::parseKey);

  private static final String MESSAGE_ID_HEADER_NAME = "webhook-id";
  private static final String MESSAGE_TIMESTAMP_HEADER_NAME = "webhook-timestamp";

  private static final Duration DEFAULT_MESSAGE_TIMESTAMP_ALLOWED_SKEW = Duration.ofMinutes(5);

  private final List<VerificationKey> verificationKeys;
  private final Duration messageTimestampAllowedSkew;

  private WebhookSignatureVerifier(Builder builder) {

    verificationKeys =
        builder.serializedVerificationKeys.stream().map(VERIFICATION_KEY_PARSER::parse).toList();

    messageTimestampAllowedSkew = builder.messageTimestampAllowedSkew;
  }

  public static Builder builder(String serializedVerificationKey) {
    return new Builder(serializedVerificationKey);
  }

  public void verify(HttpHeaders headers, String payload)
      throws WebhookSignatureVerificationException {

    String messageId = headers.firstValue(MESSAGE_ID_HEADER_NAME).orElse(null);
    if (messageId == null || messageId.isBlank()) {
      throw new WebhookSignatureVerificationException(
          "No value found for header <%s>".formatted(MESSAGE_ID_HEADER_NAME));
    }

    String messageTimestampAsString =
        headers.firstValue(MESSAGE_TIMESTAMP_HEADER_NAME).orElse(null);
    if (messageTimestampAsString == null || messageTimestampAsString.isBlank()) {
      throw new WebhookSignatureVerificationException(
          "No value found for header <%s>".formatted(MESSAGE_TIMESTAMP_HEADER_NAME));
    }

    long timestamp = verifyTimestamp(messageTimestampAsString);

    List<Signature> signatures = Signature.parseAtLeastOne(headers);
    for (Signature signature : signatures) {
      for (VerificationKey verificationKey : verificationKeys) {
        try {
          verificationKey.verify(messageId, timestamp, payload, signature);
        } catch (SignatureNotSupportedException e) {
          LOGGER.debug(e.getMessage());
        }
      }
    }

    throw new WebhookSignatureVerificationException(
        "No verification key found for any of signatures %s".formatted(signatures));
  }

  private long verifyTimestamp(String messageTimestamp)
      throws WebhookSignatureVerificationException {
    long nowInSeconds = Duration.ofNanos(System.nanoTime()).toSeconds();

    long timestamp;
    try {
      timestamp = Long.parseLong(messageTimestamp);
    } catch (NumberFormatException e) {
      throw new WebhookSignatureVerificationException(e);
    }

    if (timestamp < (nowInSeconds - messageTimestampAllowedSkew.toSeconds())) {
      throw new WebhookSignatureVerificationException(
          "Message timestamp <%s seconds> is too old compared to the current nano time <%s seconds>"
              .formatted(timestamp, messageTimestampAllowedSkew));
    }
    if (timestamp > (nowInSeconds + messageTimestampAllowedSkew.toSeconds())) {
      throw new WebhookSignatureVerificationException(
          "Message timestamp <%s seconds> is too new compared to the current nano time <%s seconds>"
              .formatted(timestamp, messageTimestampAllowedSkew));
    }
    return timestamp;
  }

  public static class Builder {
    private final List<String> serializedVerificationKeys = new ArrayList<>();
    private Duration messageTimestampAllowedSkew = DEFAULT_MESSAGE_TIMESTAMP_ALLOWED_SKEW;

    private Builder(String serializedVerificationKey) {
      serializedVerificationKeys.add(requireNonNull(serializedVerificationKey));
    }

    public Builder addSerializedVerificationKey(String serializedVerificationKey) {
      serializedVerificationKeys.add(requireNonNull(serializedVerificationKey));
      return this;
    }

    public Builder messageTimestampAllowedSkew(Duration messageTimestampAllowedSkew) {
      this.messageTimestampAllowedSkew = requireNonNull(messageTimestampAllowedSkew);
      return this;
    }

    public WebhookSignatureVerifier build() {
      return new WebhookSignatureVerifier(this);
    }
  }
}
