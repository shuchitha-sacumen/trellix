from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.exceptions import RetryableError
from trellix_dlp.models import TrellixAuthenticationModels, TrellixAWSCredentialsModels


@pytest.fixture
def client():
    authentication = TrellixAuthenticationModels(
        server_url="https://example.com",
        username="xxx",
        password="xxx",
    )
    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )
    client.aws_credentials = TrellixAWSCredentialsModels(
        aws_access_key="xxx",
        aws_secret_key="xxx",
        aws_region="us-east-1",
        bucket_name="test-bucket",
    )
    return client


def make_client_error(code):
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": "Simulated S3 error",
            }
        },
        "GetObject",
    )


def make_s3_response(content=b"raw evidence"):
    body = Mock()
    body.read.return_value = content
    return {"Body": body}


# 1. AWS credentials are required
def test_fetch_evidence_from_s3_missing_credentials(client):
    client.aws_credentials = None

    with pytest.raises(
        RuntimeError,
        match="AWS credentials are required for S3 operations",
    ):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg")


# 2. Validate incident_id
@pytest.mark.parametrize("incident_id", [None, 123, True, [], {}])
def test_fetch_evidence_from_s3_invalid_incident_id(client, incident_id):
    with pytest.raises(ValueError, match="incident_id must be a string"):
        client.fetch_evidence_from_s3(incident_id, "evidence.jpg")


@pytest.mark.parametrize("incident_id", ["", "   "])
def test_fetch_evidence_from_s3_empty_incident_id(client, incident_id):
    with pytest.raises(ValueError, match="incident_id must not be empty"):
        client.fetch_evidence_from_s3(incident_id, "evidence.jpg")


# 3. Validate file_name
@pytest.mark.parametrize("file_name", [None, 123, True, [], {}])
def test_fetch_evidence_from_s3_invalid_file_name(client, file_name):
    with pytest.raises(ValueError, match="file_name must be a string"):
        client.fetch_evidence_from_s3("incident-123", file_name)


@pytest.mark.parametrize("file_name", ["", "   "])
def test_fetch_evidence_from_s3_empty_file_name(client, file_name):
    with pytest.raises(ValueError, match="file_name must not be empty"):
        client.fetch_evidence_from_s3("incident-123", file_name)


# 4. Successful fetch returns raw bytes
@patch("trellix_dlp.client.boto3.client")
def test_fetch_evidence_from_s3_success(mock_boto_client, client):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.return_value = make_s3_response(b"\x00\x01raw evidence")

    result = client.fetch_evidence_from_s3("incident-123", "evidence.jpg")

    expected_key = "trellix-dlp/incidents/incident-123/evidence.jpg"

    assert result == b"\x00\x01raw evidence"
    assert isinstance(result, bytes)
    mock_boto_client.assert_called_once_with(
        "s3",
        aws_access_key_id="xxx",
        aws_secret_access_key="xxx",
        region_name="us-east-1",
    )
    mock_s3.get_object.assert_called_once_with(
        Bucket="test-bucket",
        Key=expected_key,
    )
    mock_s3.get_object.return_value["Body"].read.assert_called_once_with()


# 5. Non-retryable AWS ClientError
@pytest.mark.parametrize(
    "error_code",
    ["AccessDenied", "NoSuchBucket", "NoSuchKey", "InvalidAccessKeyId"],
)
@patch("trellix_dlp.client.boto3.client")
def test_fetch_evidence_from_s3_non_retryable_error(
    mock_boto_client, client, error_code
):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.side_effect = make_client_error(error_code)

    with pytest.raises(RuntimeError, match="AWS S3 fetch failed"):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg")

    mock_s3.get_object.assert_called_once()


# 6. Retryable AWS errors
@pytest.mark.parametrize(
    "error_code",
    ["429", "500", "502", "503", "504", "RequestTimeout", "SlowDown"],
)
@patch("trellix_dlp.client.boto3.client")
def test_fetch_evidence_from_s3_retryable_errors(
    mock_boto_client, client, error_code, monkeypatch
):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.side_effect = make_client_error(error_code)

    monkeypatch.setattr(
        client.fetch_evidence_from_s3.retry,
        "sleep",
        lambda _: None,
    )

    with pytest.raises(RetryableError, match=error_code):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg")

    assert mock_s3.get_object.call_count == 3


# 7. BotoCoreError retries three times
@patch("trellix_dlp.client.boto3.client")
def test_fetch_evidence_from_s3_botocore_error(mock_boto_client, client, monkeypatch):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.side_effect = BotoCoreError()

    monkeypatch.setattr(
        client.fetch_evidence_from_s3.retry,
        "sleep",
        lambda _: None,
    )

    with pytest.raises(RetryableError, match="AWS S3 error"):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg")

    assert mock_s3.get_object.call_count == 3


# 8. Unexpected errors become RuntimeError
@patch("trellix_dlp.client.boto3.client")
def test_fetch_evidence_from_s3_unexpected_error(mock_boto_client, client):
    mock_boto_client.side_effect = ValueError("Unexpected failure")

    with pytest.raises(
        RuntimeError,
        match="Error while fetching evidence from S3",
    ):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg")
