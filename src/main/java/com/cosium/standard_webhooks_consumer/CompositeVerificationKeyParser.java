package com.cosium.standard_webhooks_consumer;

import java.util.List;
import java.util.Optional;

/**
 * @author Réda Housni Alaoui
 */
class CompositeVerificationKeyParser {

  private final List<VerificationKeyParser> parsers;

  CompositeVerificationKeyParser(VerificationKeyParser... parsers) {
    this.parsers = List.of(parsers);
  }

  public VerificationKey parse(String serializedVerificationKey) {
    return parsers.stream()
        .map(verificationKeyParser -> verificationKeyParser.parse(serializedVerificationKey))
        .filter(Optional::isPresent)
        .map(Optional::get)
        .findFirst()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Could not parse verification key <%s>"
                        .formatted(conceal(serializedVerificationKey))));
  }

  private String conceal(String serializedVerificationKey) {
    int halfLength = Math.round(serializedVerificationKey.length() / 2f);
    return serializedVerificationKey.substring(0, halfLength)
        + "*".repeat(serializedVerificationKey.length() - halfLength);
  }
}
