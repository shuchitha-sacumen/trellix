import json
from unittest.mock import Mock, patch

import pytest
import requests

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.exceptions import RetryableError
from trellix_dlp.models import TrellixAuthenticationModels, TrellixRuleSetModels


@pytest.fixture
def client():
    authentication = TrellixAuthenticationModels(
        server_url="https://example.com",
        username="xxx",
        password="xxx",
    )
    return TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )


def make_ruleset_response():
    return [
        {
            "UDLP_RuleSets.RuleSetID": "61B55D9D-3684-4BED-B24D-268371EB1EBA",
            "UDLP_RuleSets.CatalogID": "D3AB4ED4-EFAB-48D2-840D-714CBF76B801",
            "UDLP_RuleSets.Name": "Test Rule Set",
            "UDLP_RuleSets.Description": "Test description",
            "UDLP_RuleSets.Enabled": 1,
            "UDLP_RuleSets.Owner": 1,
            "UDLP_RuleSets.LastModifier": 1,
            "UDLP_RuleSets.ModificationTime": "2026-09-22T23:58:00-07:00",
        }
    ]


def test_fetch_rulesets_success(client):
    payload = json.dumps(make_ruleset_response())

    response = Mock()
    response.raise_for_status.return_value = None
    response.text = f"OK: {payload}"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        result = client.fetch_rulesets()

    assert len(result) == 1
    assert isinstance(result[0], TrellixRuleSetModels)
    assert result[0].rule_set_id == "61B55D9D-3684-4BED-B24D-268371EB1EBA"
    assert result[0].catalog_id == "D3AB4ED4-EFAB-48D2-840D-714CBF76B801"
    assert result[0].name == "Test Rule Set"
    assert result[0].enabled == 1

    mock_get.assert_called_once()


def test_fetch_rulesets_empty_response(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK:"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ):
        result = client.fetch_rulesets()

    assert result == []


def test_fetch_rulesets_request_parameters(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK: []"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.fetch_rulesets()

    kwargs = mock_get.call_args.kwargs

    assert kwargs["url"] == ("https://example.com/remote/core.executeQuery")
    assert kwargs["params"][":output"] == "json"
    assert kwargs["params"]["target"] == "UDLP_RuleSets"
    assert "(select (top 6)" in kwargs["params"]["select"]
    assert kwargs["params"]["order"] == ("(order (asc UDLP_RuleSets.RuleSetID))")
    assert "where" not in kwargs["params"]
    assert kwargs["timeout"] == 10
    assert kwargs["verify"] is False


def test_fetch_rulesets_with_last_ruleset_id(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK: []"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.fetch_rulesets(top=10, last_ruleset_id="100")

    params = mock_get.call_args.kwargs["params"]

    assert "(select (top 10)" in params["select"]
    assert params["where"] == ('(gt UDLP_RuleSets.RuleSetID "100")')


def test_fetch_rulesets_epo_error_response(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "ERROR: Insufficient permissions to execute query"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="ePO Remote Command returned an error",
        ):
            client.fetch_rulesets()

    mock_get.assert_called_once()


def test_fetch_rulesets_invalid_json(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK: {invalid-json}"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="Failed to parse response",
        ):
            client.fetch_rulesets()

    mock_get.assert_called_once()


@pytest.mark.parametrize(
    ("status_code", "error_text"),
    [
        (400, "Bad Request"),
        (401, "Unauthorized"),
    ],
)
def test_fetch_rulesets_non_retryable_http_errors(client, status_code, error_text):
    response = Mock()
    response.status_code = status_code
    response.text = error_text
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        f"{status_code} HTTP Error"
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match=f"{status_code}--{error_text}",
        ):
            client.fetch_rulesets()

    mock_get.assert_called_once()


def test_fetch_rulesets_retries_then_succeeds(client, monkeypatch):
    monkeypatch.setattr(
        client.fetch_rulesets.retry,
        "sleep",
        lambda _: None,
    )

    rate_limited = Mock()
    rate_limited.status_code = 429
    rate_limited.text = "Too Many Requests"
    rate_limited.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "429 Client Error"
    )

    success = Mock()
    success.raise_for_status.return_value = None
    success.text = "OK: " + json.dumps(make_ruleset_response())

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[rate_limited, success],
    ) as mock_get:
        result = client.fetch_rulesets()

    assert len(result) == 1
    assert result[0].rule_set_id == ("61B55D9D-3684-4BED-B24D-268371EB1EBA")
    assert mock_get.call_count == 2


def test_fetch_rulesets_retries_500_three_times(client, monkeypatch):
    monkeypatch.setattr(
        client.fetch_rulesets.retry,
        "sleep",
        lambda _: None,
    )

    response = Mock()
    response.status_code = 500
    response.text = "Internal Server Error"
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "500 Server Error"
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RetryableError,
            match="500--Internal Server Error",
        ):
            client.fetch_rulesets()

    assert mock_get.call_count == 3
