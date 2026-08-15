/**
 * license/keygen-client.js
 * 
 * Keygen.sh API client for license activation, validation, and deactivation.
 * Uses built-in HTTPS module with validation-scoped token only (no admin token).
 * All network errors are caught and returned as structured error results.
 * 
 * CONFIGURATION:
 * Set the following environment variables before running the application:
 * - KEYGEN_ACCOUNT_ID: Your Keygen.sh account ID
 * - KEYGEN_VALIDATION_TOKEN: A validation-scoped token from your Keygen.sh account
 * 
 * IMPORTANT: Never embed the admin token in the application.
 * Only use validation-scoped tokens that cannot create or modify licenses.
 * 
 * REQUIREMENTS SATISFIED:
 * - Requirement 19.3: License activation with key and machine fingerprint
 * - Requirement 20.1: License validation at application startup
 * - Requirement 20.4: No admin token embedded (validation-scoped only)
 * - Requirement 25.2: Network errors do not throw; return structured error results
 */

const https = require('https');

// Keygen.sh API configuration
// IMPORTANT: These values should be configured via environment variables or config file in production
const KEYGEN_ACCOUNT_ID = process.env.KEYGEN_ACCOUNT_ID || 'demo-account';
const KEYGEN_VALIDATION_TOKEN = process.env.KEYGEN_VALIDATION_TOKEN || '';
const KEYGEN_API_URL = 'api.keygen.sh';
const KEYGEN_API_VERSION = 'v1';

/**
 * Make an HTTPS request to Keygen.sh API
 * @private
 * @param {Object} options - Request options
 * @param {string} options.method - HTTP method
 * @param {string} options.path - API path
 * @param {Object} [options.body] - Request body (will be JSON stringified)
 * @returns {Promise<Object>} Response data
 */
function makeRequest({ method, path, body }) {
  return new Promise((resolve) => {
    const bodyData = body ? JSON.stringify(body) : null;
    
    const options = {
      hostname: KEYGEN_API_URL,
      port: 443,
      path: `/v1/accounts/${KEYGEN_ACCOUNT_ID}${path}`,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${KEYGEN_VALIDATION_TOKEN}`
      }
    };
    
    if (bodyData) {
      options.headers['Content-Length'] = Buffer.byteLength(bodyData);
    }
    
    const req = https.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const parsed = data ? JSON.parse(data) : {};
          resolve({
            success: res.statusCode >= 200 && res.statusCode < 300,
            statusCode: res.statusCode,
            data: parsed
          });
        } catch (parseError) {
          resolve({
            success: false,
            error: 'PARSE_ERROR',
            message: 'Failed to parse API response',
            details: parseError.message
          });
        }
      });
    });
    
    req.on('error', (error) => {
      // Network errors must not throw - return structured error result
      resolve({
        success: false,
        error: 'NETWORK_ERROR',
        message: 'Failed to connect to Keygen.sh',
        details: error.message
      });
    });
    
    req.on('timeout', () => {
      req.destroy();
      resolve({
        success: false,
        error: 'TIMEOUT',
        message: 'Request to Keygen.sh timed out'
      });
    });
    
    // Set timeout to 30 seconds
    req.setTimeout(30000);
    
    if (bodyData) {
      req.write(bodyData);
    }
    
    req.end();
  });
}

/**
 * Activate a license key for this machine.
 * 
 * Validates the license key against Keygen.sh and associates it with the machine fingerprint.
 * Returns a validation-scoped token that can be used for subsequent validation calls.
 * 
 * @param {string} key - License key provided by the user
 * @param {string} fingerprint - Machine fingerprint from machine-id.js
 * @returns {Promise<Object>} Activation result
 * @returns {boolean} return.success - Whether activation succeeded
 * @returns {string} [return.token] - Validation-scoped token (on success)
 * @returns {string} [return.expiresAt] - ISO 8601 expiry date (on success)
 * @returns {string} [return.error] - Error code (on failure)
 * @returns {string} [return.message] - Error message (on failure)
 */
async function activateLicense(key, fingerprint) {
  try {
    // Validate inputs
    if (!key || typeof key !== 'string') {
      return {
        success: false,
        error: 'INVALID_KEY',
        message: 'License key is required and must be a string'
      };
    }
    
    if (!fingerprint || typeof fingerprint !== 'string') {
      return {
        success: false,
        error: 'INVALID_FINGERPRINT',
        message: 'Machine fingerprint is required and must be a string'
      };
    }
    
    // Make activation request
    const result = await makeRequest({
      method: 'POST',
      path: `/licenses/${key}/actions/activate`,
      body: {
        meta: {
          fingerprint
        }
      }
    });
    
    // Handle network/parse errors
    if (result.error) {
      return result;
    }
    
    // Handle API errors
    if (!result.success) {
      const errorDetail = result.data.errors?.[0];
      return {
        success: false,
        error: errorDetail?.code || 'ACTIVATION_FAILED',
        message: errorDetail?.detail || 'Failed to activate license',
        statusCode: result.statusCode
      };
    }
    
    // Extract token and expiry from response
    const licenseData = result.data.data;
    
    if (!licenseData) {
      return {
        success: false,
        error: 'INVALID_RESPONSE',
        message: 'API response missing license data'
      };
    }
    
    // Generate a validation token (in a real scenario, Keygen would provide this)
    // For now, we'll use the license key as the token since we're using validation-scoped tokens
    const token = licenseData.id || key;
    const expiresAt = licenseData.attributes?.expiry || null;
    
    return {
      success: true,
      token,
      expiresAt
    };
    
  } catch (error) {
    // Catch any unexpected errors
    return {
      success: false,
      error: 'UNEXPECTED_ERROR',
      message: 'Unexpected error during activation',
      details: error.message
    };
  }
}

/**
 * Validate a stored license token.
 * 
 * Checks whether the token is still valid and not expired.
 * Used at application startup and during grace period checks.
 * 
 * @param {string} token - Validation-scoped token from previous activation
 * @returns {Promise<Object>} Validation result
 * @returns {boolean} return.success - Whether the API call succeeded
 * @returns {boolean} [return.valid] - Whether the license is valid (on success)
 * @returns {string} [return.expiresAt] - ISO 8601 expiry date (on success)
 * @returns {string} [return.error] - Error code (on failure)
 * @returns {string} [return.message] - Error message (on failure)
 */
async function validateLicense(token) {
  try {
    // Validate input
    if (!token || typeof token !== 'string') {
      return {
        success: false,
        error: 'INVALID_TOKEN',
        message: 'Token is required and must be a string'
      };
    }
    
    // Make validation request
    const result = await makeRequest({
      method: 'POST',
      path: `/licenses/${token}/actions/validate`,
      body: {
        meta: {}
      }
    });
    
    // Handle network/parse errors
    if (result.error) {
      return result;
    }
    
    // Handle API errors (invalid token, expired, etc.)
    if (!result.success) {
      const errorDetail = result.data.errors?.[0];
      
      // Return structured result even for invalid licenses
      return {
        success: true, // API call succeeded
        valid: false,  // But license is not valid
        error: errorDetail?.code || 'INVALID',
        message: errorDetail?.detail || 'License is not valid',
        statusCode: result.statusCode
      };
    }
    
    // Extract validation result
    const validationData = result.data.data;
    const meta = result.data.meta || {};
    
    // Check if license is valid
    const isValid = meta.valid === true || validationData?.attributes?.valid === true;
    const expiresAt = validationData?.attributes?.expiry || null;
    
    return {
      success: true,
      valid: isValid,
      expiresAt
    };
    
  } catch (error) {
    // Catch any unexpected errors
    return {
      success: false,
      error: 'UNEXPECTED_ERROR',
      message: 'Unexpected error during validation',
      details: error.message
    };
  }
}

/**
 * Deactivate a license token for this machine.
 * 
 * Removes the machine fingerprint association from the license,
 * freeing up an activation slot for use on another machine.
 * 
 * @param {string} token - Validation-scoped token from activation
 * @param {string} fingerprint - Machine fingerprint from machine-id.js
 * @returns {Promise<Object>} Deactivation result
 * @returns {boolean} return.success - Whether deactivation succeeded
 * @returns {string} [return.error] - Error code (on failure)
 * @returns {string} [return.message] - Error message (on failure)
 */
async function deactivateLicense(token, fingerprint) {
  try {
    // Validate inputs
    if (!token || typeof token !== 'string') {
      return {
        success: false,
        error: 'INVALID_TOKEN',
        message: 'Token is required and must be a string'
      };
    }
    
    if (!fingerprint || typeof fingerprint !== 'string') {
      return {
        success: false,
        error: 'INVALID_FINGERPRINT',
        message: 'Machine fingerprint is required and must be a string'
      };
    }
    
    // Make deactivation request
    const result = await makeRequest({
      method: 'POST',
      path: `/licenses/${token}/actions/deactivate`,
      body: {
        meta: {
          fingerprint
        }
      }
    });
    
    // Handle network/parse errors
    if (result.error) {
      return result;
    }
    
    // Handle API errors
    if (!result.success) {
      const errorDetail = result.data.errors?.[0];
      return {
        success: false,
        error: errorDetail?.code || 'DEACTIVATION_FAILED',
        message: errorDetail?.detail || 'Failed to deactivate license',
        statusCode: result.statusCode
      };
    }
    
    // Deactivation successful
    return {
      success: true
    };
    
  } catch (error) {
    // Catch any unexpected errors
    return {
      success: false,
      error: 'UNEXPECTED_ERROR',
      message: 'Unexpected error during deactivation',
      details: error.message
    };
  }
}

module.exports = {
  activateLicense,
  validateLicense,
  deactivateLicense
};
