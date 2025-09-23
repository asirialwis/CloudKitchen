const validator = require("validator");
const xss = require("xss");

/**
 * Comprehensive Payment Validation System
 * Protects against: Price manipulation, XSS, DoS, Financial fraud
 */
class PaymentValidator {
  constructor() {
    // Configuration constants
    this.MAX_ITEMS_PER_ORDER = 100;
    this.MAX_ITEM_NAME_LENGTH = 100;
    this.MAX_ITEM_DESCRIPTION_LENGTH = 500;
    this.MAX_TOTAL_AMOUNT = 100000; // 100,000 LKR
    this.MIN_PRICE = 0.01; // 1 cent minimum
    this.MAX_PRICE = 10000; // 10,000 LKR maximum
    this.MAX_QUANTITY = 100;
    this.MIN_QUANTITY = 1;

    // Allowed image domains for security
    this.ALLOWED_IMAGE_DOMAINS = [
      "images.unsplash.com",
      "via.placeholder.com",
      "picsum.photos",
      "cloudkitchen.com",
      "cdn.cloudkitchen.com",
      "pinimg.com",
    ];

    // Malicious URL patterns
    this.MALICIOUS_PATTERNS = [
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /onload/i,
      /onerror/i,
      /onclick/i,
      /onmouseover/i,
      /onfocus/i,
      /onblur/i,
      /onchange/i,
      /onsubmit/i,
    ];
  }

  /**
   * Main validation method for payment items
   * @param {Array} items - Array of payment items
   * @returns {Object} - Validation result with sanitized data
   */
  validatePaymentItems(items) {
    const errors = [];
    const sanitizedItems = [];

    // Validate items array structure
    if (!Array.isArray(items)) {
      throw new Error("Items must be an array");
    }

    if (items.length === 0) {
      throw new Error("At least one item is required");
    }

    if (items.length > this.MAX_ITEMS_PER_ORDER) {
      throw new Error(
        `Maximum ${this.MAX_ITEMS_PER_ORDER} items allowed per order`
      );
    }

    // Validate each item
    items.forEach((item, index) => {
      try {
        const sanitizedItem = this.validatePaymentItem(item, index);
        sanitizedItems.push(sanitizedItem);
      } catch (error) {
        errors.push(`Item ${index + 1}: ${error.message}`);
      }
    });

    if (errors.length > 0) {
      throw new Error(errors.join("; "));
    }

    // Validate total amount
    const totalAmount = this.validateTotalAmount(sanitizedItems);

    return {
      isValid: true,
      items: sanitizedItems,
      totalAmount: totalAmount,
      itemCount: sanitizedItems.length,
    };
  }

  /**
   * Validate individual payment item
   * @param {Object} item - Payment item object
   * @param {number} index - Item index for error reporting
   * @returns {Object} - Sanitized item
   */
  validatePaymentItem(item, index) {
    const errors = [];

    // Validate item structure
    if (!item || typeof item !== "object") {
      throw new Error("Invalid item structure");
    }

    // Validate and sanitize item name
    const sanitizedName = this.validateAndSanitizeName(item.name, index);

    // Validate and sanitize price
    const sanitizedPrice = this.validateAndSanitizePrice(item.price, index);

    // Validate and sanitize quantity
    const sanitizedQuantity = this.validateAndSanitizeQuantity(
      item.quantity,
      index
    );

    // Validate and sanitize image URL
    const sanitizedImageUrl = this.validateAndSanitizeImageUrl(
      item.imageUrl,
      index
    );

    // Validate item ID if provided
    const sanitizedItemId = this.validateAndSanitizeItemId(item.itemId, index);

    return {
      name: sanitizedName,
      price: sanitizedPrice,
      quantity: sanitizedQuantity,
      imageUrl: sanitizedImageUrl,
      itemId: sanitizedItemId,
      description: this.sanitizeDescription(item.description || ""),
      category: this.sanitizeCategory(item.category || "general"),
    };
  }

  /**
   * Validate and sanitize item name
   */
  validateAndSanitizeName(name, index) {
    if (!name || typeof name !== "string") {
      throw new Error("Name is required and must be a string");
    }

    // XSS sanitization
    const sanitizedName = xss(validator.escape(name.trim()));

    if (sanitizedName.length < 1) {
      throw new Error("Name cannot be empty");
    }

    if (sanitizedName.length > this.MAX_ITEM_NAME_LENGTH) {
      throw new Error(
        `Name cannot exceed ${this.MAX_ITEM_NAME_LENGTH} characters`
      );
    }

    // Check for malicious patterns
    if (this.containsMaliciousPatterns(sanitizedName)) {
      throw new Error("Name contains potentially malicious content");
    }

    // Validate character set (alphanumeric, spaces, basic punctuation)
    if (!/^[a-zA-Z0-9\s\-'\.&(),]+$/.test(sanitizedName)) {
      throw new Error("Name contains invalid characters");
    }

    return sanitizedName;
  }

  /**
   * Validate and sanitize price
   */
  validateAndSanitizePrice(price, index) {
    if (typeof price !== "number") {
      throw new Error("Price must be a number");
    }

    // Check for special number values
    if (!Number.isFinite(price)) {
      throw new Error("Price must be a finite number");
    }

    if (Number.isNaN(price)) {
      throw new Error("Price cannot be NaN");
    }

    // Check for negative prices (potential refund fraud)
    if (price < 0) {
      throw new Error("Price cannot be negative");
    }

    // Check minimum price
    if (price < this.MIN_PRICE) {
      throw new Error(`Price must be at least ${this.MIN_PRICE} LKR`);
    }

    // Check maximum price
    if (price > this.MAX_PRICE) {
      throw new Error(`Price cannot exceed ${this.MAX_PRICE} LKR`);
    }

    // Round to 2 decimal places to prevent floating point issues
    const roundedPrice = Math.round(price * 100) / 100;

    return roundedPrice;
  }

  /**
   * Validate and sanitize quantity
   */
  validateAndSanitizeQuantity(quantity, index) {
    if (!Number.isInteger(quantity)) {
      throw new Error("Quantity must be an integer");
    }

    if (quantity < this.MIN_QUANTITY) {
      throw new Error(`Quantity must be at least ${this.MIN_QUANTITY}`);
    }

    if (quantity > this.MAX_QUANTITY) {
      throw new Error(`Quantity cannot exceed ${this.MAX_QUANTITY}`);
    }

    return quantity;
  }

  /**
   * Validate and sanitize image URL
   */
  validateAndSanitizeImageUrl(imageUrl, index) {
    if (!imageUrl) {
      return null; // Image URL is optional
    }

    if (typeof imageUrl !== "string") {
      throw new Error("Image URL must be a string");
    }

    const trimmedUrl = imageUrl.trim();

    // Check for malicious patterns
    if (this.containsMaliciousPatterns(trimmedUrl)) {
      throw new Error("Image URL contains potentially malicious content");
    }

    // Validate URL format
    if (
      !validator.isURL(trimmedUrl, {
        protocols: ["http", "https"],
        require_protocol: true,
      })
    ) {
      throw new Error("Invalid image URL format");
    }

    // Check domain whitelist
    try {
      const url = new URL(trimmedUrl);
      const isAllowedDomain = this.ALLOWED_IMAGE_DOMAINS.some(
        (domain) =>
          url.hostname === domain || url.hostname.endsWith("." + domain)
      );

      if (!isAllowedDomain) {
        throw new Error("Image URL domain not allowed");
      }
    } catch (error) {
      throw new Error("Invalid image URL");
    }

    return trimmedUrl;
  }

  /**
   * Validate and sanitize item ID
   */
  validateAndSanitizeItemId(itemId, index) {
    if (!itemId) {
      return null; // Item ID is optional
    }

    if (typeof itemId !== "string") {
      throw new Error("Item ID must be a string");
    }

    const trimmedId = itemId.trim();

    // Validate MongoDB ObjectId format
    if (!/^[0-9a-fA-F]{24}$/.test(trimmedId)) {
      throw new Error("Invalid item ID format");
    }

    return trimmedId;
  }

  /**
   * Sanitize description
   */
  sanitizeDescription(description) {
    if (!description || typeof description !== "string") {
      return "";
    }

    const sanitized = xss(validator.escape(description.trim()));

    if (sanitized.length > this.MAX_ITEM_DESCRIPTION_LENGTH) {
      return sanitized.substring(0, this.MAX_ITEM_DESCRIPTION_LENGTH);
    }

    return sanitized;
  }

  /**
   * Sanitize category
   */
  sanitizeCategory(category) {
    if (!category || typeof category !== "string") {
      return "general";
    }

    const sanitized = xss(validator.escape(category.trim().toLowerCase()));

    // Allowed categories
    const allowedCategories = [
      "appetizer",
      "main",
      "dessert",
      "beverage",
      "salad",
      "soup",
      "pizza",
      "burger",
      "pasta",
      "rice",
      "general",
    ];

    if (allowedCategories.includes(sanitized)) {
      return sanitized;
    }

    return "general";
  }

  /**
   * Validate total amount
   */
  validateTotalAmount(items) {
    const total = items.reduce((sum, item) => {
      return sum + item.price * item.quantity;
    }, 0);

    if (total <= 0) {
      throw new Error("Total amount must be greater than 0");
    }

    if (total > this.MAX_TOTAL_AMOUNT) {
      throw new Error(
        `Total amount cannot exceed ${this.MAX_TOTAL_AMOUNT} LKR`
      );
    }

    return Math.round(total * 100) / 100;
  }

  /**
   * Check for malicious patterns
   */
  containsMaliciousPatterns(text) {
    return this.MALICIOUS_PATTERNS.some((pattern) => pattern.test(text));
  }

  /**
   * Detect suspicious payment patterns
   */
  detectSuspiciousActivity(items, userHistory = {}) {
    const alerts = [];
    let riskScore = 0;

    // Check for unusual price patterns
    const avgPrice =
      items.reduce((sum, item) => sum + item.price, 0) / items.length;
    if (avgPrice > 1000) {
      alerts.push("Unusually high average price detected");
      riskScore += 50;
    }

    // Check for negative prices (should be caught by validation, but double-check)
    if (items.some((item) => item.price < 0)) {
      alerts.push("Negative prices detected - potential refund fraud");
      riskScore += 100;
    }

    // Check for quantity manipulation
    if (items.some((item) => item.quantity > 50)) {
      alerts.push("Unusually high quantities detected");
      riskScore += 30;
    }

    // Check for rapid successive payments
    if (userHistory.recentPayments > 5) {
      alerts.push("Rapid successive payments detected");
      riskScore += 40;
    }

    // Check for unusual total amounts
    const totalAmount = items.reduce(
      (sum, item) => sum + item.price * item.quantity,
      0
    );
    if (
      userHistory.avgOrderValue &&
      totalAmount > userHistory.avgOrderValue * 10
    ) {
      alerts.push("Unusually high total amount detected");
      riskScore += 60;
    }

    // Check for duplicate items
    const itemNames = items.map((item) => item.name);
    const uniqueNames = new Set(itemNames);
    if (itemNames.length !== uniqueNames.size) {
      alerts.push("Duplicate items detected");
      riskScore += 20;
    }

    return {
      isSuspicious: alerts.length > 0,
      alerts: alerts,
      riskScore: riskScore,
      recommendation:
        riskScore > 100 ? "BLOCK" : riskScore > 50 ? "REVIEW" : "ALLOW",
    };
  }

  /**
   * Validate payment metadata
   */
  validatePaymentMetadata(metadata) {
    const sanitizedMetadata = {};

    if (metadata && typeof metadata === "object") {
      // Sanitize metadata keys and values
      Object.keys(metadata).forEach((key) => {
        if (typeof key === "string" && key.length <= 50) {
          const sanitizedKey = xss(validator.escape(key.trim()));
          const sanitizedValue = xss(
            validator.escape(String(metadata[key]).trim())
          );

          if (sanitizedValue.length <= 200) {
            sanitizedMetadata[sanitizedKey] = sanitizedValue;
          }
        }
      });
    }

    return sanitizedMetadata;
  }
}

module.exports = PaymentValidator;
