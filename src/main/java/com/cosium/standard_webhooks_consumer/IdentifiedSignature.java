package com.cosium.standard_webhooks_consumer;

import static java.util.Objects.requireNonNull;

import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Réda Housni Alaoui
 */
record IdentifiedSignature(SignatureSchemeId schemeId, Signature content) {

  private static final Logger LOGGER = LoggerFactory.getLogger(IdentifiedSignature.class);

  private static final String MESSAGE_SIGNATURE_HEADER_NAME = "webhook-signature";

  IdentifiedSignature {
    requireNonNull(schemeId);
    requireNonNull(content);
  }

  public static List<IdentifiedSignature> parseAtLeastOne(HttpHeaders headers)
      throws WebhookSignatureVerificationException {
    String messageSignatureHeaderValue =
        headers.firstValue(MESSAGE_SIGNATURE_HEADER_NAME).orElse(null);
    if (messageSignatureHeaderValue == null || messageSignatureHeaderValue.isBlank()) {
      throw new WebhookSignatureVerificationException(
          "No value found for header <%s>".formatted(MESSAGE_SIGNATURE_HEADER_NAME));
    }

    List<IdentifiedSignature> signatures =
        Stream.of(messageSignatureHeaderValue.split(" "))
            .map(IdentifiedSignature::parse)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .toList();

    if (signatures.isEmpty()) {
      throw new WebhookSignatureVerificationException(
          "No well-formed signature(s) found for signature header value <%s>. A well-formed signature should have the form '$version,$base64encodedContent'."
              .formatted(messageSignatureHeaderValue));
    }

    return signatures;
  }

  private static Optional<IdentifiedSignature> parse(String messageSignature) {
    if (messageSignature == null || messageSignature.isBlank()) {
      return Optional.empty();
    }
    String[] signatureParts = messageSignature.split(",");
    if (signatureParts.length != 2) {
      return Optional.empty();
    }

    IdentifiedSignature signature;
    try {
      signature =
          new IdentifiedSignature(
              new SignatureSchemeId(signatureParts[0]), new Signature(signatureParts[1]));
    } catch (RuntimeException e) {
      LOGGER.warn(e.getMessage());
      return Optional.empty();
    }

    return Optional.of(signature);
  }
}
