package com.cosium.standard_webhooks_consumer;

/**
 * @author Réda Housni Alaoui
 */
interface VerificationKey {

  void verify(String messageId, long timestamp, String payload, Signature signature)
      throws SignatureNotSupportedException, WebhookSignatureVerificationException;
}
