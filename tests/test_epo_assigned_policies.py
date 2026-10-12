import json
from unittest.mock import Mock, patch

import pytest
import requests

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.exceptions import RetryableError
from trellix_dlp.models import TrellixAuthenticationModels


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


def make_assigned_policy_response():
    return [
        {
            "EPOAssignedPolicy.NodeName": "Test-System",
            "EPOAssignedPolicy.PolicyObjectID": 123,
            "EPOAssignedPolicy.PolicyDesc": "Test assigned policy",
            "EPOAssignedPolicy.FeatureTextID": "DLP",
            "EPOAssignedPolicy.CategoryTextID": 1,
            "EPOAssignedPolicy.upToDate": True,
        }
    ]


@pytest.mark.parametrize(
    "top",
    [0, -1, 1.5, "5", None, True],
)
def test_fetch_epo_assigned_policies_invalid_top(client, top):
    with pytest.raises(ValueError):
        client.fetch_epo_assigned_policies(top=top)


@pytest.mark.parametrize(
    "last_policy_object_id",
    [-1, 1.5, "123", True],
)
def test_fetch_epo_assigned_policies_invalid_cursor(client, last_policy_object_id):
    with pytest.raises(ValueError):
        client.fetch_epo_assigned_policies(last_policy_object_id=last_policy_object_id)


def test_fetch_epo_assigned_policies_success(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK: " + json.dumps(make_assigned_policy_response())

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        result = client.fetch_epo_assigned_policies()

    assert len(result) == 1
    assert result[0].node_name == "Test-System"
    assert result[0].policy_object_id == 123
    assert result[0].policy_desc == "Test assigned policy"
    assert result[0].feature_text_id == "DLP"
    assert result[0].category_text_id == 1
    assert result[0].up_to_date is True
    mock_get.assert_called_once()


def test_fetch_epo_assigned_policies_empty_response(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK:"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ):
        result = client.fetch_epo_assigned_policies()

    assert result == []


def test_fetch_epo_assigned_policies_request_parameters(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK: []"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.fetch_epo_assigned_policies(
            top=10,
            last_policy_object_id=123,
        )

    kwargs = mock_get.call_args.kwargs
    params = kwargs["params"]

    assert kwargs["url"] == ("https://example.com/remote/core.executeQuery")
    assert params[":output"] == "json"
    assert params["target"] == "EPOAssignedPolicy"
    assert "(select (top 10)" in params["select"]
    assert params["order"] == ("(order (asc EPOAssignedPolicy.PolicyObjectID))")
    assert params["where"] == ("(gt EPOAssignedPolicy.PolicyObjectID 123)")
    assert kwargs["timeout"] == 10
    assert kwargs["verify"] is False
    mock_get.assert_called_once()


@pytest.mark.parametrize(
    ("response_text", "expected_error"),
    [
        (
            "ERROR: Insufficient permissions",
            "ePO Remote Command returned an error",
        ),
        (
            "OK: {invalid-json}",
            "Failed to parse response",
        ),
        (
            "OK: [{}]",
            "Failed to parse response",
        ),
    ],
    ids=["epo-error", "invalid-json", "missing-fields"],
)
def test_fetch_epo_assigned_policies_invalid_response(
    client, response_text, expected_error
):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = response_text

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(RuntimeError, match=expected_error):
            client.fetch_epo_assigned_policies()

    mock_get.assert_called_once()


@pytest.mark.parametrize(
    ("status_code", "error_text"),
    [
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
    ],
)
def test_fetch_epo_assigned_policies_non_retryable_http(
    client, status_code, error_text
):
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
            client.fetch_epo_assigned_policies()

    mock_get.assert_called_once()


def test_fetch_epo_assigned_policies_retries_429_then_succeeds(client, monkeypatch):
    monkeypatch.setattr(
        client.fetch_epo_assigned_policies.retry,
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
    success.text = "OK: " + json.dumps(make_assigned_policy_response())

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[rate_limited, success],
    ) as mock_get:
        result = client.fetch_epo_assigned_policies()

    assert len(result) == 1
    assert result[0].policy_object_id == 123
    assert mock_get.call_count == 2


def test_fetch_epo_assigned_policies_retries_500_three_times(client, monkeypatch):
    monkeypatch.setattr(
        client.fetch_epo_assigned_policies.retry,
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
            client.fetch_epo_assigned_policies()

    assert mock_get.call_count == 3
