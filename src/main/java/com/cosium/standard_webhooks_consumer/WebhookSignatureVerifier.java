package com.cosium.standard_webhooks_consumer;

import static java.util.Objects.requireNonNull;

import java.net.http.HttpHeaders;
import java.time.Clock;
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
  private final Clock clock;
  private final Duration messageTimestampAllowedSkew;

  private WebhookSignatureVerifier(Builder builder) {

    verificationKeys =
        builder.serializedVerificationKeys.stream().map(VERIFICATION_KEY_PARSER::parse).toList();
    clock = builder.clock;
    messageTimestampAllowedSkew = builder.messageTimestampAllowedSkew;
  }

  /**
   * @param serializedVerificationKey e.g. "v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4="
   */
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

    List<WebhookSignatureVerificationException> verificationExceptions = new ArrayList<>();

    List<IdentifiedSignature> signatures = IdentifiedSignature.parseAtLeastOne(headers);
    for (IdentifiedSignature signature : signatures) {
      for (VerificationKey verificationKey : verificationKeys) {
        SignatureSchemeId signatureSchemeId = signature.schemeId();
        if (!verificationKey.supports(signatureSchemeId)) {
          LOGGER.debug("{} does not support {}", verificationKey, signatureSchemeId);
          continue;
        }
        try {
          verificationKey.verify(messageId, timestamp, payload, signature.content());
        } catch (WebhookSignatureVerificationException e) {
          verificationExceptions.add(e);
          continue;
        }
        return;
      }
    }

    if (verificationExceptions.isEmpty()) {
      throw new WebhookSignatureVerificationException(
          "No supporting verification key found for any signature among %s".formatted(signatures));
    }

    WebhookSignatureVerificationException collectingException =
        new WebhookSignatureVerificationException(
            "No signature among %s is valid".formatted(signatures));
    verificationExceptions.forEach(collectingException::addSuppressed);
    throw collectingException;
  }

  private long verifyTimestamp(String messageTimestamp)
      throws WebhookSignatureVerificationException {
    long nowInSeconds = Duration.ofMillis(clock.millis()).toSeconds();

    long timestamp;
    try {
      timestamp = Long.parseLong(messageTimestamp);
    } catch (NumberFormatException e) {
      throw new WebhookSignatureVerificationException(
          "Cannot parse timestamp <%s>".formatted(messageTimestamp));
    }

    if (timestamp < (nowInSeconds - messageTimestampAllowedSkew.toSeconds())) {
      throw new WebhookSignatureVerificationException(
          "Message timestamp <%s seconds> is too old compared to the current timestamp <%s seconds>"
              .formatted(timestamp, nowInSeconds));
    }
    if (timestamp > (nowInSeconds + messageTimestampAllowedSkew.toSeconds())) {
      throw new WebhookSignatureVerificationException(
          "Message timestamp <%s seconds> is too new compared to the current timestamp <%s seconds>"
              .formatted(timestamp, nowInSeconds));
    }
    return timestamp;
  }

  public static class Builder {
    private final List<String> serializedVerificationKeys = new ArrayList<>();
    private Duration messageTimestampAllowedSkew = DEFAULT_MESSAGE_TIMESTAMP_ALLOWED_SKEW;
    private Clock clock = Clock.systemDefaultZone();

    private Builder(String serializedVerificationKey) {
      serializedVerificationKeys.add(requireNonNull(serializedVerificationKey));
    }

    /**
     * @param serializedVerificationKey e.g. "v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4="
     */
    public Builder addSerializedVerificationKey(String serializedVerificationKey) {
      serializedVerificationKeys.add(requireNonNull(serializedVerificationKey));
      return this;
    }

    /**
     * @param messageTimestampAllowedSkew Allowable tolerance of the current timestamp to prevent
     *     replay attacks.
     */
    public Builder messageTimestampAllowedSkew(Duration messageTimestampAllowedSkew) {
      this.messageTimestampAllowedSkew = requireNonNull(messageTimestampAllowedSkew);
      return this;
    }

    public Builder clock(Clock clock) {
      this.clock = requireNonNull(clock);
      return this;
    }

    public WebhookSignatureVerifier build() {
      return new WebhookSignatureVerifier(this);
    }
  }
}
