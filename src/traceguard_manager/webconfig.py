"""Response headers shared by both applications."""

from types import MappingProxyType

# No inline scripts or styles and no third-party origins: every asset is served from /static.
CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    )
)

SECURITY_HEADERS = MappingProxyType(
    {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "same-origin",
        "x-xss-protection": "0",
        "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        "strict-transport-security": "max-age=63072000; includeSubDomains",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        "content-security-policy": CONTENT_SECURITY_POLICY,
    }
)
