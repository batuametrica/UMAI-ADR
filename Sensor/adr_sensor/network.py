"""Shared HTTP transport configuration for enterprise Windows deployments."""

import os
import ssl
import urllib.request
from typing import Optional


def proxy_url() -> Optional[str]:
    """Return the explicit UMAI proxy, falling back to standard HTTPS_PROXY."""
    return (
        os.environ.get("UMAI_HTTPS_PROXY", "").strip()
        or os.environ.get("HTTPS_PROXY", "").strip()
        or os.environ.get("https_proxy", "").strip()
        or None
    )


def ca_bundle_path() -> Optional[str]:
    return os.environ.get("UMAI_CA_BUNDLE", "").strip() or None


def build_opener() -> urllib.request.OpenerDirector:
    """Build an opener honoring an explicit proxy and an optional private CA."""
    handlers = []
    proxy = proxy_url()
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))

    ca_bundle = ca_bundle_path()
    context = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def urlopen(request: urllib.request.Request, *, timeout: int):
    """Open one request with the process-level enterprise TLS configuration."""
    return build_opener().open(request, timeout=timeout)
