"""DASHBOARD_TRUST_DEV_PRINCIPAL refuses to start inside Azure.

The flag forces every dashboard visitor's identity to one login and
ignores the EasyAuth header. Locally that is how the dashboard is driven
without GitHub; deployed, it hands the operator's identity -- and the
operator's audit button -- to anyone who can reach the URL. It was a
startup WARNING, which is a line in a log nobody reads until afterwards.
Inside Azure Container Apps it is now a refusal to start.

Detection is CONTAINER_APP_NAME, which the Container Apps runtime sets in
every container it runs; a developer machine does not have it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from codeguard.api.main import DevPrincipalInAzure, app, refuse_dev_principal_in_azure
from codeguard.config import Settings, get_settings


def _settings(trust: bool) -> Settings:
    base = get_settings().model_dump()
    base.update({"dashboard_trust_dev_principal": trust, "dashboard_dev_principal": "someone"})
    return Settings(**base)


def test_refused_in_azure():
    with pytest.raises(DevPrincipalInAzure, match="DASHBOARD_TRUST_DEV_PRINCIPAL"):
        refuse_dev_principal_in_azure(_settings(True), {"CONTAINER_APP_NAME": "codeguard-api"})


def test_allowed_locally():
    refuse_dev_principal_in_azure(_settings(True), {})


def test_azure_without_the_flag_is_fine():
    refuse_dev_principal_in_azure(_settings(False), {"CONTAINER_APP_NAME": "codeguard-api"})


def test_an_empty_container_app_name_is_not_azure():
    refuse_dev_principal_in_azure(_settings(True), {"CONTAINER_APP_NAME": ""})


def test_the_app_does_not_start(monkeypatch):
    monkeypatch.setenv("CONTAINER_APP_NAME", "codeguard-api")
    monkeypatch.setattr("codeguard.api.main.get_settings", lambda: _settings(True))
    with pytest.raises(DevPrincipalInAzure):
        with TestClient(app):
            pass
