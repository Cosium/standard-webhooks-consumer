package com.cosium.standard_webhooks_consumer;

/**
 * @author Réda Housni Alaoui
 */
interface VerificationKey {

  boolean supports(SignatureSchemeId signatureSchemeId);

  void verify(String messageId, long timestamp, String payload, Signature signatureToVerify)
      throws WebhookSignatureVerificationException;
}
