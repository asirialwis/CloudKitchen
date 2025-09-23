/**
 * Security Tests for Payment Service
 * Tests various attack scenarios to ensure validation works correctly
 */

const PaymentValidator = require("../validators/paymentValidator");
const FraudDetection = require("../middleware/fraudDetection");

class SecurityTests {
  constructor() {
    this.validator = new PaymentValidator();
    this.fraudDetection = new FraudDetection();
    this.testResults = [];
  }

  /**
   * Run all security tests
   */
  async runAllTests() {
    console.log("🔒 Starting Payment Service Security Tests...\n");

    this.testNegativePriceAttack();
    this.testPriceOverflowAttack();
    this.testXSSInProductName();
    this.testMaliciousImageUrl();
    this.testQuantityManipulation();
    this.testExtremeQuantities();
    this.testMaliciousMetadata();
    this.testFraudDetection();
    this.testInputValidation();

    this.printResults();
  }

  /**
   * Test negative price attack
   */
  testNegativePriceAttack() {
    console.log("Testing: Negative Price Attack");

    const maliciousPayload = [
      {
        name: "Expensive Item",
        price: -999.99, // Negative price
        quantity: 1,
        imageUrl: "https://images.unsplash.com/photo-1234567890",
      },
    ];

    try {
      this.validator.validatePaymentItems(maliciousPayload);
      this.addTestResult(
        "Negative Price Attack",
        false,
        "Validation should have failed"
      );
    } catch (error) {
      if (error.message.includes("Price cannot be negative")) {
        this.addTestResult(
          "Negative Price Attack",
          true,
          "Successfully blocked negative prices"
        );
      } else {
        this.addTestResult(
          "Negative Price Attack",
          false,
          `Unexpected error: ${error.message}`
        );
      }
    }
  }

  /**
   * Test price overflow attack
   */
  testPriceOverflowAttack() {
    console.log("Testing: Price Overflow Attack");

    const maliciousPayload = [
      {
        name: "Cheap Item",
        price: 999999999.99, // Extremely high price
        quantity: 1,
        imageUrl: "https://images.unsplash.com/photo-1234567890",
      },
    ];

    try {
      this.validator.validatePaymentItems(maliciousPayload);
      this.addTestResult(
        "Price Overflow Attack",
        false,
        "Validation should have failed"
      );
    } catch (error) {
      if (error.message.includes("Price cannot exceed")) {
        this.addTestResult(
          "Price Overflow Attack",
          true,
          "Successfully blocked extreme prices"
        );
      } else {
        this.addTestResult(
          "Price Overflow Attack",
          false,
          `Unexpected error: ${error.message}`
        );
      }
    }
  }

  /**
   * Test XSS in product name
   */
  testXSSInProductName() {
    console.log("Testing: XSS in Product Name");

    const maliciousPayload = [
      {
        name: "<script>alert('XSS')</script>",
        price: 10.0,
        quantity: 1,
        imageUrl: "https://images.unsplash.com/photo-1234567890",
      },
    ];

    try {
      const result = this.validator.validatePaymentItems(maliciousPayload);
      if (result.items[0].name.includes("<script>")) {
        this.addTestResult(
          "XSS in Product Name",
          false,
          "XSS payload not sanitized"
        );
      } else {
        this.addTestResult(
          "XSS in Product Name",
          true,
          "XSS payload successfully sanitized"
        );
      }
    } catch (error) {
      // XSS payload should be blocked by malicious pattern detection
      if (
        error.message.includes("malicious content") ||
        error.message.includes("invalid characters")
      ) {
        this.addTestResult(
          "XSS in Product Name",
          true,
          "XSS payload blocked by validation"
        );
      } else {
        this.addTestResult(
          "XSS in Product Name",
          false,
          `Unexpected error: ${error.message}`
        );
      }
    }
  }

  /**
   * Test malicious image URL
   */
  testMaliciousImageUrl() {
    console.log("Testing: Malicious Image URL");

    const maliciousPayload = [
      {
        name: "Legitimate Item",
        price: 10.0,
        quantity: 1,
        imageUrl: "javascript:alert('XSS')",
      },
    ];

    try {
      this.validator.validatePaymentItems(maliciousPayload);
      this.addTestResult(
        "Malicious Image URL",
        false,
        "Validation should have failed"
      );
    } catch (error) {
      if (
        error.message.includes("malicious content") ||
        error.message.includes("domain not allowed")
      ) {
        this.addTestResult(
          "Malicious Image URL",
          true,
          "Successfully blocked malicious URL"
        );
      } else {
        this.addTestResult(
          "Malicious Image URL",
          false,
          `Unexpected error: ${error.message}`
        );
      }
    }
  }

  /**
   * Test quantity manipulation
   */
  testQuantityManipulation() {
    console.log("Testing: Quantity Manipulation");

    const maliciousPayload = [
      {
        name: "Expensive Item",
        price: 100.0,
        quantity: 2147483647, // Max integer value
        imageUrl: "https://images.unsplash.com/photo-1234567890",
      },
    ];

    try {
      this.validator.validatePaymentItems(maliciousPayload);
      this.addTestResult(
        "Quantity Manipulation",
        false,
        "Validation should have failed"
      );
    } catch (error) {
      if (error.message.includes("Quantity cannot exceed")) {
        this.addTestResult(
          "Quantity Manipulation",
          true,
          "Successfully blocked extreme quantities"
        );
      } else {
        this.addTestResult(
          "Quantity Manipulation",
          false,
          `Unexpected error: ${error.message}`
        );
      }
    }
  }

  /**
   * Test extreme quantities
   */
  testExtremeQuantities() {
    console.log("Testing: Extreme Quantities");

    const maliciousPayload = [
      {
        name: "Item 1",
        price: 10.0,
        quantity: 1000, // This exceeds MAX_QUANTITY (100)
        imageUrl: "https://images.unsplash.com/photo-1234567890",
      },
    ];

    try {
      this.validator.validatePaymentItems(maliciousPayload);
      this.addTestResult(
        "Extreme Quantities",
        false,
        "Validation should have failed"
      );
    } catch (error) {
      if (
        error.message.includes("Quantity cannot exceed") ||
        error.message.includes("Total amount cannot exceed")
      ) {
        this.addTestResult(
          "Extreme Quantities",
          true,
          "Successfully blocked extreme quantities"
        );
      } else {
        this.addTestResult(
          "Extreme Quantities",
          false,
          `Unexpected error: ${error.message}`
        );
      }
    }
  }

  /**
   * Test malicious metadata
   */
  testMaliciousMetadata() {
    console.log("Testing: Malicious Metadata");

    const maliciousMetadata = {
      user_id: "507f1f77bcf86cd799439011",
      malicious_script: "<script>alert('XSS')</script>",
      normal_field: "legitimate_value",
    };

    const sanitized = this.validator.validatePaymentMetadata(maliciousMetadata);

    if (
      sanitized.malicious_script &&
      sanitized.malicious_script.includes("<script>")
    ) {
      this.addTestResult(
        "Malicious Metadata",
        false,
        "Malicious content not sanitized"
      );
    } else {
      this.addTestResult(
        "Malicious Metadata",
        true,
        "Malicious content successfully sanitized"
      );
    }
  }

  /**
   * Test fraud detection
   */
  testFraudDetection() {
    console.log("Testing: Fraud Detection");

    const suspiciousItems = [
      {
        name: "Expensive Item",
        price: 5000.0, // High price
        quantity: 100, // High quantity
        imageUrl: "https://images.unsplash.com/photo-1234567890",
      },
    ];

    const mockReq = {
      headers: {
        "x-user-id": "507f1f77bcf86cd799439011",
        "user-agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      },
      ip: "192.168.1.100",
    };

    const userHistory = {
      recentPayments: 15, // High number of recent payments
      avgOrderValue: 100, // Much lower than current order
      totalOrders: 5,
    };

    const fraudResult = this.fraudDetection.detectFraud(
      mockReq,
      {
        items: suspiciousItems,
        totalAmount: 500000,
      },
      userHistory
    );

    if (fraudResult.isSuspicious && fraudResult.riskScore > 50) {
      this.addTestResult(
        "Fraud Detection",
        true,
        `Successfully detected suspicious activity (Risk Score: ${fraudResult.riskScore})`
      );
    } else {
      this.addTestResult(
        "Fraud Detection",
        false,
        "Failed to detect suspicious activity"
      );
    }
  }

  /**
   * Test input validation
   */
  testInputValidation() {
    console.log("Testing: Input Validation");

    const invalidInputs = [
      { name: null, price: 10, quantity: 1 },
      { name: "Item", price: "not_a_number", quantity: 1 },
      { name: "Item", price: 10, quantity: "not_a_number" },
      { name: "", price: 10, quantity: 1 },
      { name: "Item", price: 0, quantity: 1 },
      { name: "Item", price: 10, quantity: 0 },
    ];

    let passedTests = 0;
    let totalTests = invalidInputs.length;

    invalidInputs.forEach((input, index) => {
      try {
        this.validator.validatePaymentItems([input]);
        console.log(
          `  ❌ Test ${index + 1} failed: Should have rejected invalid input`
        );
      } catch (error) {
        passedTests++;
        console.log(
          `  ✅ Test ${index + 1} passed: Correctly rejected invalid input`
        );
      }
    });

    if (passedTests === totalTests) {
      this.addTestResult(
        "Input Validation",
        true,
        `All ${totalTests} validation tests passed`
      );
    } else {
      this.addTestResult(
        "Input Validation",
        false,
        `Only ${passedTests}/${totalTests} validation tests passed`
      );
    }
  }

  /**
   * Add test result
   */
  addTestResult(testName, passed, message) {
    this.testResults.push({
      testName,
      passed,
      message,
      timestamp: new Date().toISOString(),
    });

    const status = passed ? "✅ PASS" : "❌ FAIL";
    console.log(`  ${status}: ${message}\n`);
  }

  /**
   * Print test results summary
   */
  printResults() {
    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(
      (result) => result.passed
    ).length;
    const failedTests = totalTests - passedTests;

    console.log("📊 Security Test Results Summary:");
    console.log("=====================================");
    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${passedTests}`);
    console.log(`Failed: ${failedTests}`);
    console.log(
      `Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%\n`
    );

    if (failedTests > 0) {
      console.log("❌ Failed Tests:");
      this.testResults
        .filter((result) => !result.passed)
        .forEach((result) => {
          console.log(`  - ${result.testName}: ${result.message}`);
        });
    }

    if (passedTests === totalTests) {
      console.log("🎉 All security tests passed! Payment service is secure.");
    } else {
      console.log(
        "⚠️ Some security tests failed. Please review and fix the issues."
      );
    }
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  const tests = new SecurityTests();
  tests.runAllTests().catch(console.error);
}

module.exports = SecurityTests;
