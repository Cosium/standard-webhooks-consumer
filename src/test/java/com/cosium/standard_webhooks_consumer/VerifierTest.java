package com.cosium.standard_webhooks_consumer;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.http.HttpHeaders;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * @author Réda Housni Alaoui
 */
class VerifierTest {

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify valid signature")
  void test1(String verificationKey, String signature)
      throws WebhookSignatureVerificationException {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));
    verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo'",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,J/b6YbswScYdpR1AvAXOM2HR/jdSzawexEQ+N/6dHBcKtvJFd9yivsCDkwVE6A1G2C9wFFwQENUhio5rNrpiAw=='"
  })
  @DisplayName("Verify invalid signature")
  void test2(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageMatching("No signature among \\[.+] is valid");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify invalid payload")
  void test3(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageMatching("No signature among \\[.+] is valid");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify invalid timestamp")
  void test4(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987216),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageMatching("No signature among \\[.+] is valid");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify invalid message id")
  void test5(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd6",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageMatching("No signature among \\[.+] is valid");
  }

  @Test
  @DisplayName("Build with malformed verification key")
  void test6() {
    WebhookSignatureVerifier.Builder builder =
        WebhookSignatureVerifier.builder("foo_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=")
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()));

    assertThatThrownBy(builder::build)
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining(
            "Could not parse verification key <foo_b6Ovv5eS7H5seJrGSStB************************>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io='"
  })
  @DisplayName("Verify missing signature header")
  void test7(String verificationKey) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215)));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining("No value found for header <webhook-signature>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io='"
  })
  @DisplayName("Verify blank signature header")
  void test8(String verificationKey) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                " "));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining("No value found for header <webhook-signature>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io='"
  })
  @DisplayName("Verify malformed signature header")
  void test9(String verificationKey) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                "iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo="));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining(
            "No well-formed signature(s) found for signature header value <iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo=>. A well-formed signature should have the form '$version,$base64encodedContent'.");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=',',iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=',',XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify malformed signature header")
  void test10(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining(
            "No well-formed signature(s) found for signature header value <%s>. A well-formed signature should have the form '$version,$base64encodedContent'.",
            signature);
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify missing message id")
  void test11(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-timestamp", String.valueOf(1737987215), "webhook-signature", signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining("No value found for header <webhook-id>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify blank message id")
  void test12(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                " ",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining("No value found for header <webhook-id>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify missing timestamp")
  void test13(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining("No value found for header <webhook-timestamp>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify blank timestamp")
  void test14(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                "",
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining("No value found for header <webhook-timestamp>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify unparseable timestamp")
  void test15(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                "yo",
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining("Cannot parse timestamp <yo>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify too old timestamp")
  void test16(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(
                Clock.fixed(
                    Instant.ofEpochSecond(1737987215 + Duration.ofMinutes(10).toSeconds()),
                    ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining(
            "Message timestamp <1737987215 seconds> is too old compared to the current timestamp <1737987815 seconds>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify too new timestamp")
  void test17(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(
                Clock.fixed(
                    Instant.ofEpochSecond(1737987215 - Duration.ofMinutes(10).toSeconds()),
                    ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageContaining(
            "Message timestamp <1737987215 seconds> is too new compared to the current timestamp <1737986615 seconds>");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v2,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v2a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify unknown signature scheme id")
  void test18(String verificationKey, String signature) {
    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

    assertThatThrownBy(() -> verifier.verify(httpHeaders, "{\"greetings\": \"Hello World\"}"))
        .isInstanceOf(WebhookSignatureVerificationException.class)
        .hasMessageMatching(
            "No supporting verification key found for any signature among \\[IdentifiedSignature\\[.+]]]");
  }

  @ParameterizedTest
  @CsvSource({
    "'whsec_b6Ovv5eS7H5seJrGSStBYDivs8v2/KrFjfMaVZYsi7w=','v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo v1,iayM3VaiYCEDP/CxWUFWcxUCJk2YmBDQHtHTsaHzrwo='",
    "'whpk_MCowBQYDK2VwAyEAkp3dScDPIzT1CwUFUMdzyPbWOAQaCF9z4ucuKuZD7Io=','v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg= v1a,XVbiOe+IzCKsXBuhb52iHLroqxFJofJNMQRL80I2kWO0+kXu2gcqgXAzontxDDgpMDw6SMh4sjzr+67EmUUzDg=='"
  })
  @DisplayName("Verify request holding an invalid signature plus a valid signature")
  void test19(String verificationKey, String signature)
      throws WebhookSignatureVerificationException {

    WebhookSignatureVerifier verifier =
        WebhookSignatureVerifier.builder(verificationKey)
            .clock(Clock.fixed(Instant.ofEpochSecond(1737987215), ZoneId.systemDefault()))
            .build();
    HttpHeaders httpHeaders =
        createHttpHeaders(
            Map.of(
                "webhook-id",
                "7a2486b3-31cf-4bd3-a460-df8845d16cd5",
                "webhook-timestamp",
                String.valueOf(1737987215),
                "webhook-signature",
                signature));

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
