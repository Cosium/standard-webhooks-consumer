package com.cosium.standard_webhooks_consumer;

import java.util.Base64;

/**
 * @author Réda Housni Alaoui
 */
record Signature(String base64EncodedValue) {

  Signature {
    if (base64EncodedValue == null || base64EncodedValue.isBlank()) {
      throw new IllegalArgumentException("base64EncodedValue cannot be blank");
    }
  }

  public byte[] decode() {
    return Base64.getDecoder().decode(base64EncodedValue);
  }
}
