[![Build Status](https://github.com/Cosium/standard-webhooks-consumer/actions/workflows/ci.yml/badge.svg)](https://github.com/Cosium/standard-webhooks-consumer/actions/workflows/ci.yml)
![Maven Central Version](https://img.shields.io/maven-central/v/com.cosium.standard_webhooks_consumer/standard-webhooks-consumer)

# Standard Webhooks Consumer

https://www.standardwebhooks.com/ consumer side java library.

# Maven dependency

```xml
<dependency>
  <groupId>com.cosium.standard_webhooks_consumer</groupId>
  <artifactId>standard-webhooks-consumer</artifactId>
  <version>${standard-webhooks-consumer.version}</version>
</dependency>
```

# Signature verification

```java
public class App {

  public void verifySymmetricSignature() throws WebhookSignatureVerificationException {

    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder("whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=")
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                "v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo="));
    verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}");
  }

  public void verifyAsymmetricSignature() throws WebhookSignatureVerificationException {

    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(
                "whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=")
            .build();

    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                "v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=="));

    verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}");
  }

  private HttpHeaders createHttpHeaders(Map<String, String> headers) {
    return HttpHeaders.of(
        headers.entrySet().stream()
            .map(entry -> Map.entry(entry.getKey(), List.of(entry.getValue())))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)),
        (s, s2) -> true);
  }
}

```