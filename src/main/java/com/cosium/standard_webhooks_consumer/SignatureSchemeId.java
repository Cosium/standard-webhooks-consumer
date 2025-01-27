package com.cosium.standard_webhooks_consumer;

/**
 * @author Réda Housni Alaoui
 */
record SignatureSchemeId(String value) {

  SignatureSchemeId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("The value cannot be blank");
    }
  }
}
