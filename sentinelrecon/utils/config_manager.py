"""
Configuration management for SentinelRecon
Handles API keys, settings, encrypted storage
"""

import json
import os
from pathlib import Path
from typing import Any, Optional, Dict
from cryptography.fernet import Fernet
from sentinelrecon.utils.exceptions import ConfigException


class ConfigManager:
    """Manage configuration and API keys for SentinelRecon"""

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize config manager
        
        Args:
            config_file: Path to config file
                        If None, uses ~/.sentinelrecon/config.json
        """
        if config_file is None:
            config_dir = Path.home() / ".sentinelrecon"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_file = str(config_dir / "config.json")
        
        self.config_file = Path(config_file)
        self.config = self._load_config()
        self._cipher_suite = self._get_cipher_suite()

    def _load_config(self) -> dict:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return self._get_default_config()
        else:
            return self._get_default_config()

    def _get_default_config(self) -> dict:
        """Get default configuration"""
        return {
            "api_provider": "claude",
            "claude_api_key": None,
            "openai_api_key": None,
            "nvd_api_key": None,
            "default_scan_timeout": 5,
            "default_thread_count": 10,
            "default_ports": "1-1024",
            "beginner_mode": True,
            "theme": "dark",
            "auto_ai_analysis": True,
            "auto_cve_lookup": True,
        }

    def _save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            raise ConfigException(f"Failed to save config: {e}") from e

    def _get_cipher_suite(self) -> Fernet:
        """Get or create encryption cipher suite"""
        key_file = self.config_file.parent / ".key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            # Restrict file permissions
            try:
                os.chmod(key_file, 0o600)
            except Exception:
                pass
        
        return Fernet(key)

    def encrypt_api_key(self, api_key: str) -> str:
        """
        Encrypt an API key
        
        Args:
            api_key: Plain text API key
            
        Returns:
            Encrypted API key (as string)
        """
        encrypted = self._cipher_suite.encrypt(api_key.encode())
        return encrypted.decode()

    def decrypt_api_key(self, encrypted_key: str) -> str:
        """
        Decrypt an API key
        
        Args:
            encrypted_key: Encrypted API key (as string)
            
        Returns:
            Plain text API key
        """
        try:
            decrypted = self._cipher_suite.decrypt(encrypted_key.encode())
            return decrypted.decode()
        except Exception as e:
            raise ConfigException(f"Failed to decrypt API key: {e}") from e

    def set(self, key: str, value: Any, encrypt: bool = False):
        """
        Set a configuration value
        
        Args:
            key: Configuration key
            value: Configuration value
            encrypt: Whether to encrypt the value (for API keys)
        """
        if encrypt and isinstance(value, str):
            value = self.encrypt_api_key(value)
        
        self.config[key] = value
        self._save_config()

    def get(self, key: str, default: Any = None, decrypt: bool = False) -> Any:
        """
        Get a configuration value
        
        Args:
            key: Configuration key
            default: Default value if key not found
            decrypt: Whether to decrypt the value (for API keys)
            
        Returns:
            Configuration value
        """
        value = self.config.get(key, default)
        
        if decrypt and isinstance(value, str) and value:
            try:
                value = self.decrypt_api_key(value)
            except Exception:
                pass
        
        return value

    def set_api_key(self, provider: str, api_key: str):
        """
        Set API key for provider
        
        Args:
            provider: Provider name ('claude', 'openai', 'nvd')
            api_key: API key value
        """
        key_map = {
            'claude': 'claude_api_key',
            'openai': 'openai_api_key',
            'nvd': 'nvd_api_key',
        }
        
        if provider not in key_map:
            raise ConfigException(f"Unknown provider: {provider}")
        
        config_key = key_map[provider]
        self.set(config_key, api_key, encrypt=True)

    def get_api_key(self, provider: str) -> Optional[str]:
        """
        Get API key for provider
        
        Args:
            provider: Provider name ('claude', 'openai', 'nvd')
            
        Returns:
            API key or None if not configured
        """
        key_map = {
            'claude': 'claude_api_key',
            'openai': 'openai_api_key',
            'nvd': 'nvd_api_key',
        }
        
        if provider not in key_map:
            return None
        
        config_key = key_map[provider]
        return self.get(config_key, decrypt=True)

    def has_api_key(self, provider: str) -> bool:
        """Check if API key is configured for provider"""
        return bool(self.get_api_key(provider))

    def validate_api_keys(self) -> Dict[str, bool]:
        """
        Validate that all configured API keys are present
        
        Returns:
            Dictionary with provider: has_key pairs
        """
        return {
            'claude': self.has_api_key('claude'),
            'openai': self.has_api_key('openai'),
            'nvd': self.has_api_key('nvd'),
        }

    def get_all(self) -> dict:
        """Get all configuration (without sensitive data)"""
        config_copy = self.config.copy()
        # Remove encrypted keys from public view
        for key in ['claude_api_key', 'openai_api_key', 'nvd_api_key']:
            if config_copy.get(key):
                config_copy[key] = '***ENCRYPTED***'
        return config_copy

    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self._get_default_config()
        self._save_config()
