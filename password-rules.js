/**
 * password-rules.js — the customer password policy, in ONE place.
 *
 * Loaded by the Sign Up page (<script src="password-rules.js">) to tick the
 * requirements off as the customer types, AND required by the backend
 * (backend/security.js) to enforce them. Because both read this same file, the
 * checklist on the page can never show a green tick for a password the server
 * would then refuse, or the other way round.
 *
 * Policy (customer accounts):
 *   - at least 12 characters
 *   - at least 3 of: lower-case, upper-case, numbers, special characters
 *   - no more than 2 identical characters in a row ("aab" ok, "aaa" not)
 *
 * Deliberately free of anything browser- or Node-specific.
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PasswordRules = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var MIN_LENGTH = 12;
  var MAX_LENGTH = 200;
  var MIN_CATEGORIES = 3;

  /**
   * Which individual requirements a password meets. Every field is a boolean
   * except `categories`, the count of character kinds present.
   */
  function evaluate(password) {
    var pw = String(password == null ? "" : password);
    var lower = /[a-z]/.test(pw);
    var upper = /[A-Z]/.test(pw);
    var number = /[0-9]/.test(pw);
    // Anything that is not a plain letter or digit counts as special, so a
    // space or "ñ" is treated the same on the page and on the server.
    var special = /[^A-Za-z0-9]/.test(pw);
    var categories = [lower, upper, number, special].filter(Boolean).length;
    return {
      length: pw.length >= MIN_LENGTH,
      lower: lower,
      upper: upper,
      number: number,
      special: special,
      categories: categories,
      variety: categories >= MIN_CATEGORIES,
      // Three of the same character in a row, e.g. "aaa" or "111".
      noTriples: !/(.)\1\1/.test(pw),
      notTooLong: pw.length <= MAX_LENGTH,
    };
  }

  /** True only when every requirement is met. */
  function isValid(password) {
    var r = evaluate(password);
    return r.length && r.variety && r.noTriples && r.notTooLong;
  }

  /** The first unmet requirement as a sentence, or null when all are met. */
  function firstProblem(password) {
    var r = evaluate(password);
    if (!r.length) return "Password must be at least " + MIN_LENGTH + " characters.";
    if (!r.notTooLong) return "Password must be " + MAX_LENGTH + " characters or fewer.";
    if (!r.variety) {
      return "Password must contain at least 3 of: lower-case letters, upper-case letters, " +
             "numbers, and special characters.";
    }
    if (!r.noTriples) return "Password must not have more than 2 identical characters in a row.";
    return null;
  }

  return {
    MIN_LENGTH: MIN_LENGTH,
    MAX_LENGTH: MAX_LENGTH,
    MIN_CATEGORIES: MIN_CATEGORIES,
    evaluate: evaluate,
    isValid: isValid,
    firstProblem: firstProblem,
  };
});
