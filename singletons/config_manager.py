"""
Configuration Manager Singleton for Connectly API.
Provides centralized access to application configuration settings.
"""

from typing import Any, Dict


class ConfigManager:
    _instance = None
    _initialized = False

    def __new__(cls) -> 'ConfigManager':
        if not cls._instance:
            cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self._initialize()
            ConfigManager._initialized = True

    def _initialize(self) -> None:
        """Initialize default configuration settings."""
        self.settings: Dict[str, Any] = {
            "DEFAULT_PAGE_SIZE": 20,
            "ENABLE_ANALYTICS": True,
            "RATE_LIMIT": 100,
            "MAX_FILE_SIZE": 10 * 1024 * 1024,  # 10MB
            "ALLOWED_FILE_TYPES": ["image/jpeg", "image/png", "video/mp4"],
            "API_VERSION": "1.0.0"
        }

    def get_setting(self, key: str) -> Any:
        """
        Get a configuration setting by key.
        
        Args:
            key: The configuration key to retrieve
            
        Returns:
            The configuration value or None if not found
        """
        return self.settings.get(key)

    def set_setting(self, key: str, value: Any) -> None:
        """
        Update a configuration setting.
        
        Args:
            key: The configuration key to update
            value: The new value to set
        """
        self.settings[key] = value

    def get_all_settings(self) -> Dict[str, Any]:
        """
        Get all configuration settings.
        
        Returns:
            Dictionary containing all configuration settings
        """
        return self.settings.copy() 