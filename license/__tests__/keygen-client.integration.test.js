/**
 * license/__tests__/keygen-client.integration.test.js
 * 
 * Integration test demonstrating the complete license flow.
 * Note: These tests use mocked API responses since we don't have a real Keygen.sh account.
 * In production, these would test against a staging Keygen.sh account.
 */

const { describe, it, expect, beforeEach } = require('@jest/globals');
const https = require('https');

jest.mock('https');

const { activateLicense, validateLicense, deactivateLicense } = require('../keygen-client');

describe('License flow integration', () => {
  let mockRequest;
  let mockResponse;
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    mockResponse = {
      statusCode: 200,
      on: jest.fn()
    };
    
    mockRequest = {
      on: jest.fn(),
      setTimeout: jest.fn(),
      write: jest.fn(),
      end: jest.fn(),
      destroy: jest.fn()
    };
    
    https.request.mockImplementation((options, callback) => {
      if (callback) {
        callback(mockResponse);
      }
      return mockRequest;
    });
  });
  
  it('should complete full license lifecycle: activate -> validate -> deactivate', async () => {
    const testKey = 'TEST-LICENSE-KEY-123';
    const testFingerprint = 'machine-fingerprint-abc123';
    let testToken;
    
    // Step 1: Activate license
    {
      const activateResponse = JSON.stringify({
        data: {
          id: 'license-token-xyz',
          type: 'licenses',
          attributes: {
            expiry: '2025-12-31T23:59:59.000Z',
            valid: true
          }
        }
      });
      
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(activateResponse));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const activateResult = await activateLicense(testKey, testFingerprint);
      
      expect(activateResult.success).toBe(true);
      expect(activateResult.token).toBeDefined();
      expect(activateResult.expiresAt).toBe('2025-12-31T23:59:59.000Z');
      
      testToken = activateResult.token;
    }
    
    // Step 2: Validate the activated license
    {
      const validateResponse = JSON.stringify({
        data: {
          type: 'licenses',
          attributes: {
            expiry: '2025-12-31T23:59:59.000Z',
            valid: true
          }
        },
        meta: {
          valid: true
        }
      });
      
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(validateResponse));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const validateResult = await validateLicense(testToken);
      
      expect(validateResult.success).toBe(true);
      expect(validateResult.valid).toBe(true);
      expect(validateResult.expiresAt).toBe('2025-12-31T23:59:59.000Z');
    }
    
    // Step 3: Deactivate license
    {
      const deactivateResponse = JSON.stringify({
        data: {
          type: 'licenses',
          attributes: {}
        }
      });
      
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(deactivateResponse));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const deactivateResult = await deactivateLicense(testToken, testFingerprint);
      
      expect(deactivateResult.success).toBe(true);
    }
  });
  
  it('should handle grace period scenario: network down after successful activation', async () => {
    const testToken = 'stored-token-xyz';
    
    // Simulate network error during validation (API unreachable)
    mockRequest.on.mockImplementation((event, handler) => {
      if (event === 'error') {
        setImmediate(() => handler(new Error('ENETUNREACH')));
      }
    });
    
    const validateResult = await validateLicense(testToken);
    
    // API call failed due to network
    expect(validateResult.success).toBe(false);
    expect(validateResult.error).toBe('NETWORK_ERROR');
    expect(validateResult.message).toContain('Failed to connect');
    
    // Application layer should check storedAt timestamp and apply grace period logic
    // (This would be handled in the main process, not in keygen-client itself)
  });
  
  it('should handle expired license scenario', async () => {
    const testToken = 'expired-token';
    
    mockResponse.statusCode = 422;
    
    const expiredResponse = JSON.stringify({
      errors: [{
        code: 'EXPIRED',
        detail: 'License has expired'
      }]
    });
    
    mockResponse.on.mockImplementation((event, handler) => {
      if (event === 'data') {
        setImmediate(() => handler(expiredResponse));
      } else if (event === 'end') {
        setImmediate(() => handler());
      }
    });
    
    const validateResult = await validateLicense(testToken);
    
    expect(validateResult.success).toBe(true); // API call succeeded
    expect(validateResult.valid).toBe(false);  // But license is expired
    expect(validateResult.error).toBe('EXPIRED');
  });
  
  it('should handle activation with already-used fingerprint', async () => {
    const testKey = 'TEST-KEY';
    const testFingerprint = 'already-used-fingerprint';
    
    mockResponse.statusCode = 422;
    
    const errorResponse = JSON.stringify({
      errors: [{
        code: 'FINGERPRINT_TAKEN',
        detail: 'This machine fingerprint is already associated with another activation'
      }]
    });
    
    mockResponse.on.mockImplementation((event, handler) => {
      if (event === 'data') {
        setImmediate(() => handler(errorResponse));
      } else if (event === 'end') {
        setImmediate(() => handler());
      }
    });
    
    const activateResult = await activateLicense(testKey, testFingerprint);
    
    expect(activateResult.success).toBe(false);
    expect(activateResult.error).toBe('FINGERPRINT_TAKEN');
    expect(activateResult.message).toContain('already');
  });
});
