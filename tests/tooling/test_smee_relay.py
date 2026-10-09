"""The local webhook relay (docker-compose.yml's `smee` service).

The GitHub App's Webhook URL pointed at the Azure app, which is disabled,
so a local stack received nothing. smee.io relays deliveries to localhost.
What has to stay true of the service:

  * It is opt-in. Under the `tunnel` profile, so a plain `docker compose up`
    never starts forwarding real deliveries into whatever is running.
  * It is pinned. An exact node image and an exact smee-client version,
    never `latest` -- npx would otherwise fetch whatever was published
    that morning and run it.
  * It targets the api over the compose network.
  * The channel URL comes from SMEE_URL in .env and is never written into
    the file. A smee channel is readable by anyone holding its URL.
  * It never receives .env. The relay forwards bytes; it has no use for
    the webhook secret, the App key path or the Anthropic key, and a
    container that never holds them cannot leak them. Signature checking
    is unchanged: the api verifies X-Hub-Signature-256, which smee
    forwards untouched.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"


def _service() -> dict:
    services = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))["services"]
    assert "smee" in services, "no smee relay service"
    return services["smee"]


def _command() -> str:
    command = _service()["command"]
    return " ".join(command) if isinstance(command, list) else command


def test_the_relay_only_starts_with_the_tunnel_profile():
    assert _service().get("profiles") == ["tunnel"]


def test_the_image_and_the_client_are_pinned_exactly():
    image = _service()["image"]
    assert re.fullmatch(r"node:\d+\.\d+\.\d+-alpine", image), image
    assert re.search(r"smee-client@\d+\.\d+\.\d+\b", _command()), _command()


def test_it_forwards_to_the_api_webhook():
    assert "--target http://api:8000/webhook" in _command()
    assert "api" in _service().get("depends_on", {})


def test_the_channel_comes_from_smee_url_and_is_never_in_the_file():
    assert '--url "$$SMEE_URL"' in _command()
    assert _service()["environment"] == {"SMEE_URL": "${SMEE_URL:-}"}
    assert "smee.io/" not in _COMPOSE.read_text(encoding="utf-8").replace("https://smee.io/new", "")


def test_an_unset_smee_url_does_not_break_other_compose_commands():
    """Compose interpolates every service whatever its profile, so a `:?`
    here made `docker compose ps` fail for anyone without SMEE_URL. The
    relay checks for it itself and exits with a message instead."""
    assert "${SMEE_URL:?" not in _COMPOSE.read_text(encoding="utf-8")
    assert 'test -n "$$SMEE_URL"' in _command()


def test_the_relay_is_given_no_secrets():
    service = _service()
    assert "env_file" not in service
    assert set(service["environment"]) == {"SMEE_URL"}
    assert "volumes" not in service
