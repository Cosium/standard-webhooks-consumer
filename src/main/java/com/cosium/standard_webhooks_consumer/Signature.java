package com.cosium.standard_webhooks_consumer;

import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Réda Housni Alaoui
 */
record Signature(String schemeId, String base64EncodedSignature) {

  private static final Logger LOGGER = LoggerFactory.getLogger(Signature.class);

  private static final String MESSAGE_SIGNATURE_HEADER_NAME = "webhook-signature";

  Signature {
    if (schemeId == null || schemeId.isBlank()) {
      throw new IllegalArgumentException("Version cannot be null or blank");
    }
    if (base64EncodedSignature == null || base64EncodedSignature.isBlank()) {
      throw new IllegalArgumentException("Base64EncodedSignature cannot be null or blank");
    }
  }

  public static List<Signature> parseAtLeastOne(HttpHeaders headers)
      throws WebhookSignatureVerificationException {
    String messageSignatureHeaderValue =
        headers.firstValue(MESSAGE_SIGNATURE_HEADER_NAME).orElse(null);
    if (messageSignatureHeaderValue == null || messageSignatureHeaderValue.isBlank()) {
      throw new WebhookSignatureVerificationException(
          "No value found for header <%s>".formatted(MESSAGE_SIGNATURE_HEADER_NAME));
    }

    List<Signature> signatures =
        Stream.of(messageSignatureHeaderValue.split(" "))
            .map(Signature::createSignature)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .toList();

    if (signatures.isEmpty()) {
      throw new WebhookSignatureVerificationException(
          "No signature found for header value <%s>".formatted(messageSignatureHeaderValue));
    }

    return signatures;
  }

  private static Optional<Signature> createSignature(String messageSignature) {
    if (messageSignature == null || messageSignature.isBlank()) {
      return Optional.empty();
    }
    String[] signatureParts = messageSignature.split(",");
    if (signatureParts.length != 2) {
      return Optional.empty();
    }

    Signature signature;
    try {
      signature = new Signature(signatureParts[0], signatureParts[1]);
    } catch (RuntimeException e) {
      LOGGER.warn(e.getMessage());
      return Optional.empty();
    }

    return Optional.of(signature);
  }
}
