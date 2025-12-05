"""JWT Compression Library for Python
3-header design: header + payload + signature for IdP compatibility
"""

import json
import base64
import os
import logging

logger = logging.getLogger(__name__)

# Note: JWT header is always transmitted via x-jwt-header
# No default header - supports all IdPs (Auth0, Okta, Azure, Google with kid/jku/x5t)


def is_jwt_compression_enabled():
    """Check if JWT compression is enabled via environment variable"""
    return os.environ.get('ENABLE_JWT_COMPRESSION', 'false').lower() == 'true'


def base64url_decode(data):
    """Decode base64url string"""
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)


def base64url_encode(data):
    """Encode to base64url string (no padding)"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def decompose_jwt(jwt):
    """Decompose JWT for optimized transmission
    
    Args:
        jwt (str): Full JWT token
        
    Returns:
        dict: Dictionary with header, payload (raw JSON), and signature
    
    Operations: 1 base64 decode (payload only)
    """
    if not jwt:
        return None
    
    parts = jwt.split('.')
    if len(parts) != 3:
        logger.warning('Invalid JWT format')
        return None
    
    header_b64, payload_b64, signature_b64 = parts
    
    try:
        # Decode payload only - ONLY OPERATION
        payload_json = base64url_decode(payload_b64).decode('utf-8')
        
        result = {
            'header': header_b64,         # Keep as-is (supports IdPs with kid, jku, etc.)
            'payload': payload_json,      # Raw JSON (~25% smaller than base64)
            'signature': signature_b64    # Keep as-is
        }
        
        return result
        
    except Exception as err:
        logger.warning(f'Failed to decompose JWT: {err}')
        return None


def reassemble_jwt(metadata):
    """Reassemble JWT from header, raw JSON payload, and signature
    
    Args:
        metadata: gRPC metadata tuple list
        
    Returns:
        str|None: Reassembled JWT or None
    
    Operations: 1 base64 encode (payload only)
    """
    # Convert metadata to dict
    metadata_dict = {}
    for key, value in metadata:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        metadata_dict[key] = value
    
    # Check for compressed JWT components (new format)
    payload_header = metadata_dict.get('x-jwt-payload')
    signature = metadata_dict.get('x-jwt-sig')
    header_b64 = metadata_dict.get('x-jwt-header')
    
    if payload_header and signature and header_b64:
        try:
            # Base64url encode the raw JSON payload - ONLY OPERATION
            payload_b64 = base64url_encode(payload_header)
            
            # Reassemble JWT using original header
            jwt = f'{header_b64}.{payload_b64}.{signature}'
            
            return jwt
            
        except Exception as err:
            logger.warning(f'Failed to reassemble JWT: {err}')
            return None
    
    # Fall back to standard authorization header
    auth_header = metadata_dict.get('authorization')
    if auth_header and auth_header.startswith('Bearer '):
        jwt = auth_header[7:]
        return jwt
    
    return None


def add_compressed_jwt(metadata, jwt):
    """Add compressed JWT to metadata
    
    Args:
        metadata: gRPC metadata tuple list
        jwt (str): Full JWT token
    """
    if not jwt or not is_jwt_compression_enabled():
        # Fallback to standard authorization header
        metadata.append(('authorization', f'Bearer {jwt}'))
        return
    
    components = decompose_jwt(jwt)
    if not components:
        # Failed to decompose, use standard header
        metadata.append(('authorization', f'Bearer {jwt}'))
        return
    
    # Add compressed components: header + raw JSON payload + signature
    metadata.append(('x-jwt-header', components['header']))
    metadata.append(('x-jwt-payload', components['payload']))
    metadata.append(('x-jwt-sig', components['signature']))
