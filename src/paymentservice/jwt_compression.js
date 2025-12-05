// JWT Compression Library for Node.js
// 3-header design: header + payload + signature for IdP compatibility

const logger = require('./logger');

// Note: JWT header is always transmitted via x-jwt-header
// No default header - supports all IdPs (Auth0, Okta, Azure, Google with kid/jku/x5t)

/**
 * Check if JWT compression is enabled via environment variable
 */
function isJWTCompressionEnabled() {
  return process.env.ENABLE_JWT_COMPRESSION === 'true';
}

/**
 * Decompose JWT for optimized transmission
 * @param {string} jwt - Full JWT token
 * @returns {Object} Object with header, payload (raw JSON), and signature
 * Operations: 1 base64 decode (payload only)
 */
function decomposeJWT(jwt) {
  if (!jwt) {
    return null;
  }

  const parts = jwt.split('.');
  if (parts.length !== 3) {
    logger.warn('Invalid JWT format');
    return null;
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  try {
    // Decode payload only - ONLY OPERATION
    const payloadJson = Buffer.from(payloadB64, 'base64url').toString('utf8');

    const result = {
      header: headerB64,       // Keep as-is (supports IdPs with kid, jku, etc.)
      payload: payloadJson,    // Raw JSON (~25% smaller than base64)
      signature: signatureB64  // Keep as-is
    };

    return result;
  } catch (err) {
    logger.warn(`Failed to decompose JWT: ${err.message}`);
    return null;
  }
}

/**
 * Reassemble JWT from header, raw JSON payload, and signature
 * @param {Object} metadata - gRPC metadata object containing x-jwt-header, x-jwt-payload, and x-jwt-sig headers
 * @returns {string|null} Reassembled JWT or null
 * Operations: 1 base64 encode (payload only)
 */
function reassembleJWT(metadata) {
  // Check for compressed JWT components (new format)
  const payloadHeader = getMetadataValue(metadata, 'x-jwt-payload');
  const signature = getMetadataValue(metadata, 'x-jwt-sig');

  const headerB64 = getMetadataValue(metadata, 'x-jwt-header');
  
  if (payloadHeader && signature && headerB64) {
    try {
      // Base64url encode the raw JSON payload - ONLY OPERATION
      const payloadB64 = Buffer.from(payloadHeader, 'utf8').toString('base64url');

      // Reassemble JWT using original header
      const jwt = `${headerB64}.${payloadB64}.${signature}`;

      return jwt;
    } catch (err) {
      logger.warn(`Failed to reassemble JWT: ${err.message}`);
      return null;
    }
  }

  // Fall back to standard authorization header
  const authHeader = getMetadataValue(metadata, 'authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const jwt = authHeader.substring(7);
    logger.debug(`JWT extracted from authorization header (${jwt.length} bytes)`);
    return jwt;
  }

  return null;
}

/**
 * Get metadata value (handles gRPC metadata format)
 * @param {Object} metadata - gRPC metadata object
 * @param {string} key - Metadata key
 * @returns {string|null} Metadata value or null
 */
function getMetadataValue(metadata, key) {
  try {
    const value = metadata.get(key);
    
    if (value && value.length > 0) {
      // Handle both string and Buffer values
      const val = value[0];
      if (Buffer.isBuffer(val)) {
        return val.toString('utf8');
      }
      return val;
    }
  } catch (err) {
    logger.warn(`Error getting metadata '${key}': ${err.message}`);
  }
  return null;
}

/**
 * Add compressed JWT to metadata
 * @param {Object} metadata - gRPC metadata object
 * @param {string} jwt - Full JWT token
 */
function addCompressedJWT(metadata, jwt) {
  if (!jwt || !isJWTCompressionEnabled()) {
    // Fallback to standard authorization header
    metadata.set('authorization', `Bearer ${jwt}`);
    return;
  }

  const components = decomposeJWT(jwt);
  if (!components) {
    // Failed to decompose, use standard header
    metadata.set('authorization', `Bearer ${jwt}`);
    return;
  }

  // Add compressed components: header + raw JSON payload + signature
  metadata.set('x-jwt-header', components.header);
  metadata.set('x-jwt-payload', components.payload);
  metadata.set('x-jwt-sig', components.signature);
}

module.exports = {
  isJWTCompressionEnabled,
  decomposeJWT,
  reassembleJWT,
  addCompressedJWT,
  getMetadataValue
};
