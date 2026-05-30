"""Post the brief to #vigil via the OWUI channel webhook.

Endpoint shape (verified against running OWUI 0.9.5 against the live OpenAPI
spec):

  POST /api/v1/channels/webhooks/{webhook_id}/{token}
  body: {"content": "<message>"}

The spec mentions a REST channel-message endpoint as a fallback. That route
(`/api/v1/channels/{id}/messages/post`) requires an authenticated Bearer
token, which isn't currently provisioned — leaving the fallback as a TODO
so we don't ship a half-working code path. If the webhook fails, the email
leg in deliver.py still gets the brief through; if both fail, notify.sh
pages on the same two channels with a much smaller payload.

The webhook URL is read in full from secrets/owui-webhook (chmod 600).
Storing the URL (not id/token separately) keeps post.py and notify.sh
parsing identical and avoids re-assembling on every call.
"""
from __future__ import annotations

import httpx

from . import _paths

TIMEOUT = 30.0
WEBHOOK_FILENAME = "owui-webhook"


def _webhook_url() -> str:
    p = _paths.secrets_dir() / WEBHOOK_FILENAME
    if not p.exists():
        raise RuntimeError(f"owui-webhook secret missing: {p}")
    url = p.read_text().strip()
    if not url.startswith(("http://", "https://")):
        raise RuntimeError(f"owui-webhook does not contain a URL: {p}")
    return url


def post(content: str) -> None:
    """Post `content` as a message to #vigil via the channel webhook.

    Raises on transport failure or non-2xx response. The caller decides
    whether to swallow the error (success path: log + continue) or fail
    hard (failure path: notify).
    """
    url = _webhook_url()
    r = httpx.post(
        url,
        json={"content": content},
        timeout=TIMEOUT,
        follow_redirects=True,
    )
    r.raise_for_status()
