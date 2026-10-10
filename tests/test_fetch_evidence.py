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


def make_response(content=b"test evidence", status_code=200, text="OK"):
    response = Mock()
    response.status_code = status_code
    response.text = text
    response.content = content

    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(
            f"{status_code} Error"
        )

    return response


# 1. Validate file_location
@pytest.mark.parametrize(
    "file_location",
    [None, 123, True, [], {}],
)
def test_fetch_evidence_invalid_file_location_type(client, file_location):
    with pytest.raises(ValueError, match="file_location must be a string"):
        client.fetch_evidence(file_location)


@pytest.mark.parametrize("file_location", ["", "   ", "\n"])
def test_fetch_evidence_empty_file_location(client, file_location):
    with pytest.raises(ValueError, match="file_location must not be empty"):
        client.fetch_evidence(file_location)


# 2. Successful request returns raw bytes
@patch("trellix_dlp.client.requests.post")
def test_fetch_evidence_success(mock_post, client):
    evidence = b"\x00\x01\x02raw-evidence"
    mock_post.return_value = make_response(content=evidence)

    result = client.fetch_evidence(r"\\epo-server\DLP-Evidence\sample.dlpenc")

    assert result == evidence
    assert isinstance(result, bytes)
    mock_post.assert_called_once()

    kwargs = mock_post.call_args.kwargs
    assert kwargs["timeout"] == 30
    assert kwargs["verify"] is False


# 3. Network share path is URL-encoded
@patch("trellix_dlp.client.requests.post")
def test_fetch_evidence_encodes_file_location(mock_post, client):
    mock_post.return_value = make_response()

    file_location = r"\\epo-server\DLP-Evidence\folder\sample file.dlpenc"
    client.fetch_evidence(file_location)

    requested_url = mock_post.call_args.kwargs["url"]
    assert "fileLocation=" in requested_url
    assert "%5C%5C" in requested_url
    assert "%20" in requested_url
    assert "sample file.dlpenc" not in requested_url


# 4. Non-retryable HTTP errors
@pytest.mark.parametrize("status_code", [400, 401, 403, 404])
@patch("trellix_dlp.client.requests.post")
def test_fetch_evidence_non_retryable_http_error(
    mock_post, client, status_code, monkeypatch
):
    mock_post.return_value = make_response(
        status_code=status_code,
        text="Request failed",
    )

    with pytest.raises(RuntimeError, match=f"{status_code}--Request failed"):
        client.fetch_evidence(r"\\epo-server\DLP-Evidence\sample.dlpenc")

    mock_post.assert_called_once()


# 5. HTTP 429 retries and then succeeds
@patch("trellix_dlp.client.requests.post")
def test_fetch_evidence_retries_429_then_succeeds(mock_post, client, monkeypatch):
    mock_post.side_effect = [
        make_response(status_code=429, text="Too Many Requests"),
        make_response(content=b"evidence"),
    ]
    monkeypatch.setattr(client.fetch_evidence.retry, "sleep", lambda _: None)

    result = client.fetch_evidence(r"\\epo-server\DLP-Evidence\sample.dlpenc")

    assert result == b"evidence"
    assert mock_post.call_count == 2


# 6. HTTP 500 retries three times, then raises RetryableError
@patch("trellix_dlp.client.requests.post")
def test_fetch_evidence_retries_500_three_times(mock_post, client, monkeypatch):
    mock_post.return_value = make_response(
        status_code=500,
        text="Internal Server Error",
    )
    monkeypatch.setattr(client.fetch_evidence.retry, "sleep", lambda _: None)

    with pytest.raises(RetryableError, match="500--Internal Server Error"):
        client.fetch_evidence(r"\\epo-server\DLP-Evidence\sample.dlpenc")

    assert mock_post.call_count == 3


# 7. Connection error retries three times
@patch("trellix_dlp.client.requests.post")
def test_fetch_evidence_connection_error(mock_post, client, monkeypatch):
    mock_post.side_effect = requests.ConnectionError("Connection refused")
    monkeypatch.setattr(client.fetch_evidence.retry, "sleep", lambda _: None)

    with pytest.raises(
        RetryableError,
        match="ConnectionError: Unable to connect to Trellix ePO",
    ):
        client.fetch_evidence(r"\\epo-server\DLP-Evidence\sample.dlpenc")

    assert mock_post.call_count == 3


# 8. Timeout is not retried
@patch("trellix_dlp.client.requests.post")
def test_fetch_evidence_timeout(mock_post, client):
    mock_post.side_effect = requests.Timeout("Request timed out")

    with pytest.raises(
        RuntimeError,
        match="Request timed out while trying to fetch DLP evidence",
    ):
        client.fetch_evidence(r"\\epo-server\DLP-Evidence\sample.dlpenc")

    mock_post.assert_called_once()


# 9. Other request errors are converted to RuntimeError
@patch("trellix_dlp.client.requests.post")
def test_fetch_evidence_other_request_error(mock_post, client):
    mock_post.side_effect = requests.RequestException("Unexpected request error")

    with pytest.raises(
        RuntimeError,
        match="Error during request: Unexpected request error",
    ):
        client.fetch_evidence(r"\\epo-server\DLP-Evidence\sample.dlpenc")

    mock_post.assert_called_once()
