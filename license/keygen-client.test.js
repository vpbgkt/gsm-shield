/**
 * license/keygen-client.test.js
 * 
 * Unit tests for Keygen.sh API client.
 * Tests activation, validation, and deactivation with mocked HTTPS responses.
 */

const { describe, it, expect, beforeEach } = require('@jest/globals');
const https = require('https');

// Mock the https module
jest.mock('https');

const { activateLicense, validateLicense, deactivateLicense } = require('./keygen-client');

describe('keygen-client', () => {
  let mockRequest;
  let mockResponse;
  
  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
    
    // Create mock response object
    mockResponse = {
      statusCode: 200,
      on: jest.fn()
    };
    
    // Create mock request object
    mockRequest = {
      on: jest.fn(),
      setTimeout: jest.fn(),
      write: jest.fn(),
      end: jest.fn(),
      destroy: jest.fn()
    };
    
    // Setup default https.request mock
    https.request.mockImplementation((options, callback) => {
      // Call the callback immediately with the mock response
      if (callback) {
        callback(mockResponse);
      }
      return mockRequest;
    });
  });
  
  describe('activateLicense', () => {
    it('should successfully activate a valid license', async () => {
      const responseData = JSON.stringify({
        data: {
          id: 'test-license-id',
          type: 'licenses',
          attributes: {
            expiry: '2025-12-31T23:59:59.000Z',
            valid: true
          }
        }
      });
      
      // Setup response mock to emit data and end events
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(responseData));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const result = await activateLicense('TEST-KEY-123', 'fingerprint-abc123');
      
      expect(result.success).toBe(true);
      expect(result.token).toBe('test-license-id');
      expect(result.expiresAt).toBe('2025-12-31T23:59:59.000Z');
      expect(result.error).toBeUndefined();
    });
    
    it('should return error for invalid key input', async () => {
      const result = await activateLicense('', 'fingerprint-abc123');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('INVALID_KEY');
      expect(result.message).toContain('License key is required');
    });
    
    it('should return error for invalid fingerprint input', async () => {
      const result = await activateLicense('TEST-KEY-123', '');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('INVALID_FINGERPRINT');
      expect(result.message).toContain('Machine fingerprint is required');
    });
    
    it('should handle API error responses', async () => {
      mockResponse.statusCode = 422;
      
      const responseData = JSON.stringify({
        errors: [{
          code: 'FINGERPRINT_TAKEN',
          detail: 'Machine fingerprint is already activated'
        }]
      });
      
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(responseData));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const result = await activateLicense('TEST-KEY-123', 'fingerprint-abc123');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('FINGERPRINT_TAKEN');
      expect(result.message).toContain('already activated');
    });
    
    it('should handle network errors gracefully', async () => {
      // Mock network error
      mockRequest.on.mockImplementation((event, handler) => {
        if (event === 'error') {
          setImmediate(() => handler(new Error('ECONNREFUSED')));
        }
      });
      
      const result = await activateLicense('TEST-KEY-123', 'fingerprint-abc123');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('NETWORK_ERROR');
      expect(result.message).toContain('Failed to connect');
    });
    
    it('should handle timeout errors', async () => {
      mockRequest.on.mockImplementation((event, handler) => {
        if (event === 'timeout') {
          setImmediate(() => handler());
        }
      });
      
      const result = await activateLicense('TEST-KEY-123', 'fingerprint-abc123');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('TIMEOUT');
      expect(result.message).toContain('timed out');
    });
    
    it('should handle malformed JSON responses', async () => {
      const responseData = 'not valid json{{{';
      
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(responseData));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const result = await activateLicense('TEST-KEY-123', 'fingerprint-abc123');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('PARSE_ERROR');
      expect(result.message).toContain('Failed to parse');
    });
  });
  
  describe('validateLicense', () => {
    it('should successfully validate a valid license', async () => {
      const responseData = JSON.stringify({
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
          setImmediate(() => handler(responseData));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const result = await validateLicense('test-token');
      
      expect(result.success).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.expiresAt).toBe('2025-12-31T23:59:59.000Z');
    });
    
    it('should return invalid for expired license', async () => {
      mockResponse.statusCode = 422;
      
      const responseData = JSON.stringify({
        errors: [{
          code: 'EXPIRED',
          detail: 'License has expired'
        }]
      });
      
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(responseData));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const result = await validateLicense('test-token');
      
      expect(result.success).toBe(true); // API call succeeded
      expect(result.valid).toBe(false);  // License is not valid
      expect(result.error).toBe('EXPIRED');
    });
    
    it('should return error for invalid token input', async () => {
      const result = await validateLicense('');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('INVALID_TOKEN');
      expect(result.message).toContain('Token is required');
    });
    
    it('should handle network errors gracefully', async () => {
      mockRequest.on.mockImplementation((event, handler) => {
        if (event === 'error') {
          setImmediate(() => handler(new Error('Network unreachable')));
        }
      });
      
      const result = await validateLicense('test-token');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('NETWORK_ERROR');
      expect(result.message).toContain('Failed to connect');
    });
  });
  
  describe('deactivateLicense', () => {
    it('should successfully deactivate a license', async () => {
      const responseData = JSON.stringify({
        data: {
          type: 'licenses',
          attributes: {}
        }
      });
      
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(responseData));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const result = await deactivateLicense('test-token', 'fingerprint-abc123');
      
      expect(result.success).toBe(true);
      expect(result.error).toBeUndefined();
    });
    
    it('should return error for invalid token input', async () => {
      const result = await deactivateLicense('', 'fingerprint-abc123');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('INVALID_TOKEN');
      expect(result.message).toContain('Token is required');
    });
    
    it('should return error for invalid fingerprint input', async () => {
      const result = await deactivateLicense('test-token', null);
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('INVALID_FINGERPRINT');
      expect(result.message).toContain('Machine fingerprint is required');
    });
    
    it('should handle API error responses', async () => {
      mockResponse.statusCode = 404;
      
      const responseData = JSON.stringify({
        errors: [{
          code: 'NOT_FOUND',
          detail: 'License not found'
        }]
      });
      
      mockResponse.on.mockImplementation((event, handler) => {
        if (event === 'data') {
          setImmediate(() => handler(responseData));
        } else if (event === 'end') {
          setImmediate(() => handler());
        }
      });
      
      const result = await deactivateLicense('test-token', 'fingerprint-abc123');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('NOT_FOUND');
      expect(result.message).toContain('not found');
    });
    
    it('should handle network errors gracefully', async () => {
      mockRequest.on.mockImplementation((event, handler) => {
        if (event === 'error') {
          setImmediate(() => handler(new Error('Connection reset')));
        }
      });
      
      const result = await deactivateLicense('test-token', 'fingerprint-abc123');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('NETWORK_ERROR');
      expect(result.message).toContain('Failed to connect');
    });
  });
  
  describe('Error resilience', () => {
    it('should never throw errors from activateLicense', async () => {
      // Even with a completely broken mock, should return error result
      https.request.mockImplementation(() => {
        throw new Error('Completely broken');
      });
      
      const result = await activateLicense('TEST-KEY', 'fingerprint');
      
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
    
    it('should never throw errors from validateLicense', async () => {
      https.request.mockImplementation(() => {
        throw new Error('Completely broken');
      });
      
      const result = await validateLicense('test-token');
      
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
    
    it('should never throw errors from deactivateLicense', async () => {
      https.request.mockImplementation(() => {
        throw new Error('Completely broken');
      });
      
      const result = await deactivateLicense('test-token', 'fingerprint');
      
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});
