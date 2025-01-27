package com.cosium.standard_webhooks_consumer;

/**
 * @author Réda Housni Alaoui
 */
public final class WebhookSignatureVerificationException extends Exception {

  WebhookSignatureVerificationException(Throwable cause) {
    super(cause);
  }

  WebhookSignatureVerificationException(String message) {
    super(message);
  }
}
