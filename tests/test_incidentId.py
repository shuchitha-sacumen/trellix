from unittest.mock import Mock, patch

import pytest
import requests
from tenacity import (
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

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


@pytest.mark.parametrize(
    "start_time",
    [-1, 1.5, "123", True, False],
)
def test_fetch_incident_ids_invalid_start_time(client, start_time):
    with pytest.raises(ValueError):
        client.fetch_incident_ids(start_time=start_time)


@pytest.mark.parametrize(
    "incident_nature",
    [0, 4, -1, 1.5, "1", True, False],
)
def test_fetch_incident_ids_invalid_incident_nature(
    client,
    incident_nature,
):
    with pytest.raises(ValueError):
        client.fetch_incident_ids(incident_nature=incident_nature)


def test_fetch_incident_ids_accepts_zero_start_time(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "incidentIds": ["123", "456"],
        "endTime": 1700000000000,
    }

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        result = client.fetch_incident_ids(
            start_time=0,
            incident_nature=1,
        )

    assert result.incident_ids == ["123", "456"]
    assert result.end_time == "1700000000000"

    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs["params"] == {
        "startTime": 0,
        "incidentNature": 1,
    }


@pytest.mark.parametrize(
    "incident_id",
    [None, -1, 1.5, "123", True, False],
)
def test_fetch_incident_details_invalid_incident_id(
    client,
    incident_id,
):
    with patch("trellix_dlp.client.requests.get") as mock_get:
        with pytest.raises(ValueError):
            client.fetch_incident_details(incident_id=incident_id)

    mock_get.assert_not_called()


@pytest.mark.parametrize(
    "incident_nature",
    [0, 4, -1, 1.5, "1", True, False],
)
def test_fetch_incident_details_invalid_incident_nature(
    client,
    incident_nature,
):
    with patch("trellix_dlp.client.requests.get") as mock_get:
        with pytest.raises(ValueError):
            client.fetch_incident_details(
                incident_id=123,
                incident_nature=incident_nature,
            )

    mock_get.assert_not_called()


@pytest.mark.parametrize("incident_nature", [1, 2, 3])
def test_fetch_incident_details_accepts_valid_incident_nature(
    client,
    incident_nature,
):
    # Validation should pass for each supported value.
    # Stop before making a network request.
    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=RuntimeError("request reached"),
    ):
        with pytest.raises(RuntimeError, match="request reached"):
            client.fetch_incident_details(
                incident_id=123,
                incident_nature=incident_nature,
            )


def make_incident_details_response():
    user_details = {
        "userPrincipalName": "test@example.com",
        "userAccount": "test-user",
        "userEmail": "test@example.com",
        "userOU": "TestOU",
        "userGroups": "TestGroup",
    }

    return {
        "generalDetails": {
            "incidentID": "123",
            "occurred_UTC": "2026-01-01T10:00:00Z",
            "occurred_Endpoint": "2026-01-01T10:00:00",
            "incidentType": "Data Loss",
            "actualAction": "Blocked",
            "failureReason": "",
            "expectedAction": "Block",
            "severity": "High",
            "status": "Open",
            "resolution": "Unresolved",
            "reviewer": "",
            "labels": [],
        },
        "endpointDetails": {
            "computerName": "TEST-PC",
            "computerIP": "192.0.2.10",
            "connectivityState": "Connected",
            "sourceApplication": "TestApp",
        },
        "eventUserDetails": user_details,
        "lastUpdatedUserDetails": user_details,
        "reportingProduct": {
            "reportingProduct": "Trellix DLP",
            "productVersion": "11.13",
            "policyName": "Test Policy",
            "applianceIP": "192.0.2.20",
            "applianceHostName": "EPO-SERVER",
        },
        "totalMatchCount": "1",
        "totalContentSize_KB": "10",
        "additionalInformation": {},
        "accessControlList": [],
        "customAttributes": {},
        "evidences": [],
        "rules": [],
        "classifications": [],
        "stakeholders": [],
        "auditLogs": [],
        "comments": [],
        "cases": [],
    }


def test_fetch_incident_details_success(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = make_incident_details_response()

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        result = client.fetch_incident_details(
            incident_id=123,
            incident_nature=1,
        )

    assert result.general_details.incident_id == "123"
    assert result.general_details.severity == "High"
    assert result.endpoint_details.computer_name == "TEST-PC"
    assert result.event_user_details.user_email == "test@example.com"
    assert result.reporting_product.policy_name == "Test Policy"
    assert result.evidences == []
    assert result.rules == []

    mock_get.assert_called_once()


def test_fetch_incident_details_request_parameters(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = make_incident_details_response()

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.fetch_incident_details(
            incident_id=123,
            incident_nature=3,
        )

    kwargs = mock_get.call_args.kwargs

    assert kwargs["url"] == ("https://example.com/rest/dlp/incidents/123")
    assert kwargs["params"] == {"incidentNature": 3}
    assert kwargs["timeout"] == 10
    assert kwargs["verify"] is False
    assert kwargs["auth"].username == "xxx"
    assert kwargs["auth"].password == "xxx"


def test_fetch_incident_details_without_incident_nature(client):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = make_incident_details_response()

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.fetch_incident_details(incident_id=123)

    assert mock_get.call_args.kwargs["params"] == {}


def test_fetch_incident_details_http_400(client):
    response = Mock()
    response.status_code = 400
    response.text = "Bad Request"
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "400 Client Error"
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(RuntimeError, match="400--Bad Request"):
            client.fetch_incident_details(incident_id=123)

    mock_get.assert_called_once()


def test_fetch_incident_details_http_401(client):
    response = Mock()
    response.status_code = 401
    response.text = "Unauthorized"
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "401 Client Error"
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(RuntimeError, match="401--Unauthorized"):
            client.fetch_incident_details(incident_id=123)

    mock_get.assert_called_once()


def test_fetch_incident_details_retries_429_then_succeeds(client, monkeypatch):
    rate_limited = Mock()
    rate_limited.status_code = 429
    rate_limited.text = "Too Many Requests"
    rate_limited.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "429 Client Error"
    )

    success = Mock()
    success.raise_for_status.return_value = None
    success.json.return_value = make_incident_details_response()

    # Disable retry delays during the test.
    monkeypatch.setattr(
        client.fetch_incident_details.retry,
        "sleep",
        lambda _: None,
    )

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[rate_limited, success],
    ) as mock_get:
        result = client.fetch_incident_details(incident_id=123)

    assert result.general_details.incident_id == "123"
    assert mock_get.call_count == 2


def test_fetch_incident_details_retries_500_three_times(client, monkeypatch):
    response = Mock()
    response.status_code = 500
    response.text = "Internal Server Error"
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "500 Server Error"
    )

    # Disable waiting between retries so the test runs quickly.
    monkeypatch.setattr(
        client.fetch_incident_details.retry,
        "sleep",
        lambda _: None,
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RetryableError,
            match="500--Internal Server Error",
        ):
            client.fetch_incident_details(incident_id=123)

    # Initial attempt + 2 retries = 3 requests.
    assert mock_get.call_count == 3


def test_fetch_incident_details_retries_connection_error_three_times(
    client, monkeypatch
):
    monkeypatch.setattr(
        client.fetch_incident_details.retry,
        "sleep",
        lambda _: None,
    )

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=requests.exceptions.ConnectionError("Connection failed"),
    ) as mock_get:
        with pytest.raises(
            RetryableError,
            match="ConnectionError: Unable to connect",
        ):
            client.fetch_incident_details(incident_id=123)

    assert mock_get.call_count == 3


def test_fetch_incident_details_timeout_does_not_retry(client):
    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=requests.exceptions.Timeout("Request timed out"),
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="Request timed out while trying to get incident details",
        ):
            client.fetch_incident_details(incident_id=123)

    mock_get.assert_called_once()
