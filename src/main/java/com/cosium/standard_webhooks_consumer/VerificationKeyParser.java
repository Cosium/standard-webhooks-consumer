package com.cosium.standard_webhooks_consumer;

import java.util.Optional;

/**
 * @author Réda Housni Alaoui
 */
interface VerificationKeyParser {

  Optional<? extends VerificationKey> parse(String serializedVerificationKey);
}
