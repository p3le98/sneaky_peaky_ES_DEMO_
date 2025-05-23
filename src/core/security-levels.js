"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSecurityLevelDescription = exports.normalizeSecurityLevel = exports.SecurityLevelMapping = exports.SecurityLevel = void 0;
/**
 * Core security level definitions for the application.
 * These three tiers represent the standardized security levels used throughout the application.
 */
var SecurityLevel;
(function (SecurityLevel) {
    SecurityLevel["ESSENTIAL"] = "ESSENTIAL";
    SecurityLevel["ENHANCED"] = "ENHANCED";
    SecurityLevel["MAXIMUM"] = "MAXIMUM";
})(SecurityLevel = exports.SecurityLevel || (exports.SecurityLevel = {}));
/**
 * Mapping object to convert between different security level representations
 * This is used for backward compatibility and normalization
 */
exports.SecurityLevelMapping = {
    // Legacy mappings
    'basic': SecurityLevel.ESSENTIAL,
    'standard': SecurityLevel.ENHANCED,
    'maximum': SecurityLevel.MAXIMUM,
    'BASIC': SecurityLevel.ESSENTIAL,
    'STANDARD': SecurityLevel.ENHANCED,
    'HIGH': SecurityLevel.ENHANCED,
    'PERFORMANCE': SecurityLevel.ESSENTIAL,
    // Current mappings
    'ESSENTIAL': SecurityLevel.ESSENTIAL,
    'ENHANCED': SecurityLevel.ENHANCED,
    'MAXIMUM': SecurityLevel.MAXIMUM
};
/**
 * Helper function to convert legacy security levels to the core SecurityLevel enum
 */
function normalizeSecurityLevel(level) {
    const normalized = exports.SecurityLevelMapping[level.toLowerCase()] || exports.SecurityLevelMapping[level];
    if (normalized) {
        return normalized;
    }
    console.warn(`Unknown security level: ${level}, defaulting to ESSENTIAL`);
    return SecurityLevel.ESSENTIAL;
}
exports.normalizeSecurityLevel = normalizeSecurityLevel;
/**
 * Get a human-readable description for a security level
 */
function getSecurityLevelDescription(level) {
    switch (level) {
        case SecurityLevel.ESSENTIAL:
            return 'Basic security features for everyday use';
        case SecurityLevel.ENHANCED:
            return 'Additional security measures for sensitive communications';
        case SecurityLevel.MAXIMUM:
            return 'Highest level of security with all features enabled';
        default:
            return 'Unknown security level';
    }
}
exports.getSecurityLevelDescription = getSecurityLevelDescription;
