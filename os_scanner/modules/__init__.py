"""
OutScan modules — each module tests a specific OutSystems security dimension.
"""
from .fingerprint import FingerprintModule
from .viewname_bypass import ViewNameBypassModule
from .model_js import ModelJSModule
from .screen_enum import ScreenEnumModule
from .exposure import ExposureModule
from .config_audit import ConfigAuditModule

ALL_MODULES = {
    "fingerprint": FingerprintModule,
    "viewname":    ViewNameBypassModule,
    "model_js":    ModelJSModule,
    "screen_enum": ScreenEnumModule,
    "exposure":    ExposureModule,
    "config":      ConfigAuditModule,
}

__all__ = [
    "FingerprintModule",
    "ViewNameBypassModule",
    "ModelJSModule",
    "ScreenEnumModule",
    "ExposureModule",
    "ConfigAuditModule",
    "ALL_MODULES",
]
