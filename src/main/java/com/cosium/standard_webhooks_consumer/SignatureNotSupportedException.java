package com.cosium.standard_webhooks_consumer;

/**
 * @author Réda Housni Alaoui
 */
class SignatureNotSupportedException extends Exception {

  SignatureNotSupportedException(String message) {
    super(message);
  }
}
