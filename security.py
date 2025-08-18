"""
Security Module for TikTok Toolkit

Handles encrypted token storage, PII hashing, and secure data handling.
Implements libsodium/fernet encryption and salted hashing for sensitive data.
"""

import os
import json
import hashlib
import secrets
import base64
from typing import Optional, Dict, Any, Union
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import nacl.secret
import nacl.utils
from logger import logger


class SecurityManager:
    """Manages secure storage and handling of sensitive data"""
    
    def __init__(self, key_file: str = ".security_key"):
        self.key_file = key_file
        self._fernet_key: Optional[bytes] = None
        self._sodium_key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        
        # Initialize encryption keys
        self._initialize_keys()
    
    def _initialize_keys(self) -> None:
        """Initialize encryption keys from file or generate new ones"""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    key_data = json.loads(f.read())
                    self._salt = base64.b64decode(key_data['salt'])
                    self._fernet_key = base64.b64decode(key_data['fernet_key'])
                    self._sodium_key = base64.b64decode(key_data['sodium_key'])
            else:
                self._generate_new_keys()
                self._save_keys()
        except Exception as e:
            logger.error("SECURITY", f"Failed to initialize keys: {e}")
            self._generate_new_keys()
            self._save_keys()
    
    def _generate_new_keys(self) -> None:
        """Generate new encryption keys"""
        # Generate salt for key derivation
        self._salt = secrets.token_bytes(32)
        
        # Generate Fernet key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
        )
        password = os.environ.get('TIKTOK_SECURITY_PASSWORD', 'default_password_change_me')
        key_material = kdf.derive(password.encode())
        self._fernet_key = base64.urlsafe_b64encode(key_material)
        
        # Generate libsodium key
        self._sodium_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    
    def _save_keys(self) -> None:
        """Save encryption keys to file"""
        try:
            key_data = {
                'salt': base64.b64encode(self._salt).decode(),
                'fernet_key': base64.b64encode(self._fernet_key).decode(),
                'sodium_key': base64.b64encode(self._sodium_key).decode(),
            }
            with open(self.key_file, 'w') as f:
                json.dump(key_data, f)
        except Exception as e:
            logger.error("SECURITY", f"Failed to save keys: {e}")
    
    def encrypt_tokens(self, tokens: Dict[str, Any]) -> str:
        """Encrypt tokens using Fernet encryption"""
        try:
            fernet = Fernet(self._fernet_key)
            token_json = json.dumps(tokens)
            encrypted_data = fernet.encrypt(token_json.encode())
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error("SECURITY", f"Failed to encrypt tokens: {e}")
            raise
    
    def decrypt_tokens(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt tokens using Fernet encryption"""
        try:
            fernet = Fernet(self._fernet_key)
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted_data = fernet.decrypt(encrypted_bytes)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error("SECURITY", f"Failed to decrypt tokens: {e}")
            raise
    
    def hash_pii(self, data: str, salt: Optional[str] = None) -> str:
        """Hash PII data with salt for secure storage"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Combine data with salt and hash
        salted_data = f"{data}:{salt}".encode()
        hash_obj = hashlib.sha256(salted_data)
        return f"{hash_obj.hexdigest()}:{salt}"
    
    def verify_pii_hash(self, data: str, hash_value: str) -> bool:
        """Verify PII data against its hash"""
        try:
            stored_hash, salt = hash_value.split(':', 1)
            computed_hash = self.hash_pii(data, salt).split(':', 1)[0]
            return stored_hash == computed_hash
        except Exception:
            return False
    
    def redact_pii(self, text: str, pii_patterns: Optional[Dict[str, str]] = None) -> str:
        """Redact PII from text, replacing with hashed values"""
        if pii_patterns is None:
            pii_patterns = {
                'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'phone': r'(?:(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,3}\d{2,4})',
                'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
                'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            }
        
        import re
        redacted_text = text
        
        for pii_type, pattern in pii_patterns.items():
            def replace_with_hash(match):
                original = match.group(0)
                hashed = self.hash_pii(original)
                return f"[{pii_type.upper()}_HASH:{hashed[:16]}...]"
            
            redacted_text = re.sub(pattern, replace_with_hash, redacted_text)
        
        return redacted_text


class SecureTokenStorage:
    """Secure token storage with encryption"""
    
    def __init__(self, token_file: str = "tiktok_tokens.enc", security_manager: Optional[SecurityManager] = None):
        self.token_file = token_file
        self.security_manager = security_manager or SecurityManager()
    
    def save_tokens(self, tokens: Dict[str, Any]) -> None:
        """Save tokens with encryption"""
        try:
            encrypted_data = self.security_manager.encrypt_tokens(tokens)
            with open(self.token_file, 'w') as f:
                json.dump({'encrypted_data': encrypted_data}, f)
            logger.info("SECURITY", "Tokens saved securely")
        except Exception as e:
            logger.error("SECURITY", f"Failed to save tokens: {e}")
            raise
    
    def load_tokens(self) -> Optional[Dict[str, Any]]:
        """Load and decrypt tokens"""
        try:
            if not os.path.exists(self.token_file):
                return None
            
            with open(self.token_file, 'r') as f:
                data = json.load(f)
            
            encrypted_data = data['encrypted_data']
            tokens = self.security_manager.decrypt_tokens(encrypted_data)
            logger.info("SECURITY", "Tokens loaded securely")
            return tokens
        except Exception as e:
            logger.error("SECURITY", f"Failed to load tokens: {e}")
            return None
    
    def clear_tokens(self) -> None:
        """Securely clear stored tokens"""
        try:
            if os.path.exists(self.token_file):
                # Overwrite with random data before deletion
                with open(self.token_file, 'wb') as f:
                    f.write(secrets.token_bytes(1024))
                os.remove(self.token_file)
            logger.info("SECURITY", "Tokens cleared securely")
        except Exception as e:
            logger.error("SECURITY", f"Failed to clear tokens: {e}")


class RateLimiter:
    """Rate limiting with exponential backoff"""
    
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0, backoff_factor: float = 2.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.current_delay = base_delay
        self.last_request_time = 0.0
        self.consecutive_failures = 0
    
    def wait_if_needed(self) -> None:
        """Wait if rate limit is active"""
        import time
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.current_delay:
            sleep_time = self.current_delay - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def handle_response(self, status_code: int) -> None:
        """Handle response and adjust rate limiting"""
        if status_code in [429, 503]:  # Rate limited
            self.consecutive_failures += 1
            self.current_delay = min(
                self.base_delay * (self.backoff_factor ** self.consecutive_failures),
                self.max_delay
            )
            logger.warning("RATE_LIMIT", f"Rate limited, backing off to {self.current_delay}s")
        elif status_code == 401:  # Unauthorized
            logger.error("RATE_LIMIT", "Unauthorized request - check credentials")
        elif status_code == 200:  # Success
            if self.consecutive_failures > 0:
                self.consecutive_failures = max(0, self.consecutive_failures - 1)
                self.current_delay = max(
                    self.base_delay,
                    self.current_delay / self.backoff_factor
                )
    
    def reset(self) -> None:
        """Reset rate limiter to initial state"""
        self.current_delay = self.base_delay
        self.consecutive_failures = 0
        self.last_request_time = 0.0


# Global security manager instance
security_manager = SecurityManager()
secure_storage = SecureTokenStorage(security_manager=security_manager)
rate_limiter = RateLimiter()


def hash_pii(data: str, salt: Optional[str] = None) -> str:
    """Convenience function to hash PII data"""
    return security_manager.hash_pii(data, salt)


def redact_pii(text: str) -> str:
    """Convenience function to redact PII from text"""
    return security_manager.redact_pii(text)


def verify_pii_hash(data: str, hash_value: str) -> bool:
    """Convenience function to verify PII hash"""
    return security_manager.verify_pii_hash(data, hash_value)
