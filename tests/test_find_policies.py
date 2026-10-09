import json
from unittest.mock import Mock, patch

import pytest
import requests

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.exceptions import RetryableError
from trellix_dlp.models import TrellixAuthenticationModels, TrellixPolicyModels


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


def make_policy_response():
    return [
        {
            "productId": "PROD-1",
            "featureName": "DLP",
            "typeName": "Policy",
            "objectName": "Test Policy",
            "typeId": 1,
            "featureId": "FEATURE-1",
            "objectId": 123,
            "productName": "Trellix DLP",
            "objectNotes": "Test policy notes",
        }
    ]


def test_find_policies_success(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK: " + json.dumps(make_policy_response())

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        result = client.find_policies()

    assert len(result) == 1
    assert isinstance(result[0], TrellixPolicyModels)
    assert result[0].object_id == 123
    assert result[0].object_name == "Test Policy"
    mock_get.assert_called_once()


def test_find_policies_empty_response(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK:"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ):
        result = client.find_policies()

    assert result == []


def test_find_policies_request_parameters(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "OK: []"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.find_policies(searchText="Confidential")

    kwargs = mock_get.call_args.kwargs

    assert kwargs["url"] == ("https://example.com/remote/policy.find")
    assert kwargs["params"] == {
        ":output": "json",
        "searchText": "Confidential",
    }
    assert kwargs["timeout"] == 10
    assert kwargs["verify"] is False
    mock_get.assert_called_once()


def test_find_policies_epo_error_response(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = "ERROR: Insufficient permissions"

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="ePO Remote Command returned an error",
        ):
            client.find_policies()

    mock_get.assert_called_once()


@pytest.mark.parametrize(
    "response_text",
    [
        "OK: {invalid-json}",
        'OK: [{"productId": "PROD-1"}]',
    ],
    ids=["malformed-json", "invalid-policy-model"],
)
def test_find_policies_invalid_response(client, response_text):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = response_text

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="Failed to parse response",
        ):
            client.find_policies()

    mock_get.assert_called_once()


@pytest.mark.parametrize(
    ("status_code", "error_text"),
    [
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
    ],
)
def test_find_policies_non_retryable_http_errors(client, status_code, error_text):
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
            client.find_policies()

    mock_get.assert_called_once()


def test_find_policies_timeout_does_not_retry(client):
    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=requests.exceptions.Timeout("Request timed out"),
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="Request timed out while trying to fetch DLP policies",
        ):
            client.find_policies()

    mock_get.assert_called_once()


def test_find_policies_retries_429_then_succeeds(client, monkeypatch):
    monkeypatch.setattr(
        client.find_policies.retry,
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
    success.text = "OK: " + json.dumps(make_policy_response())

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[rate_limited, success],
    ) as mock_get:
        result = client.find_policies()

    assert len(result) == 1
    assert result[0].object_id == 123
    assert mock_get.call_count == 2


def test_find_policies_retries_500_three_times(client, monkeypatch):
    monkeypatch.setattr(
        client.find_policies.retry,
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
            client.find_policies()

    assert mock_get.call_count == 3
