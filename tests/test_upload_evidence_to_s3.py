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
    return TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )


@pytest.fixture
def aws_client(client):
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
        "PutObject",
    )


# 1. AWS credentials are required
def test_upload_evidence_missing_aws_credentials(client):
    with pytest.raises(
        RuntimeError,
        match="AWS credentials are required for S3 operations",
    ):
        client.upload_evidence_to_s3("incident-123", "evidence.jpg", b"test evidence")


# 2. Validate incident_id
@pytest.mark.parametrize("incident_id", [None, 123, True, [], {}])
def test_upload_evidence_invalid_incident_id_type(aws_client, incident_id):
    with pytest.raises(ValueError, match="incident_id must be a string"):
        aws_client.upload_evidence_to_s3(incident_id, "evidence.jpg", b"test evidence")


@pytest.mark.parametrize("incident_id", ["", "   "])
def test_upload_evidence_empty_incident_id(aws_client, incident_id):
    with pytest.raises(ValueError, match="incident_id must not be empty"):
        aws_client.upload_evidence_to_s3(incident_id, "evidence.jpg", b"test evidence")


# 3. Validate file_name
@pytest.mark.parametrize("file_name", [None, 123, True, [], {}])
def test_upload_evidence_invalid_file_name_type(aws_client, file_name):
    with pytest.raises(ValueError, match="file_name must be a string"):
        aws_client.upload_evidence_to_s3("incident-123", file_name, b"test evidence")


@pytest.mark.parametrize("file_name", ["", "   "])
def test_upload_evidence_empty_file_name(aws_client, file_name):
    with pytest.raises(ValueError, match="file_name must not be empty"):
        aws_client.upload_evidence_to_s3("incident-123", file_name, b"test evidence")


# 4. Validate evidence bytes
@pytest.mark.parametrize("evidence", [None, "text", bytearray(b"data"), 123])
def test_upload_evidence_invalid_evidence_type(aws_client, evidence):
    with pytest.raises(ValueError, match="evidence must be bytes"):
        aws_client.upload_evidence_to_s3("incident-123", "evidence.jpg", evidence)


def test_upload_evidence_empty_bytes(aws_client):
    with pytest.raises(ValueError, match="evidence must not be empty"):
        aws_client.upload_evidence_to_s3("incident-123", "evidence.jpg", b"")


# 5. Successful upload
@patch("trellix_dlp.client.boto3.client")
def test_upload_evidence_success(mock_boto_client, aws_client):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3

    result = aws_client.upload_evidence_to_s3(
        "incident-123",
        "evidence.jpg",
        b"raw evidence content",
    )

    expected_key = "trellix-dlp/incidents/incident-123/evidence.jpg"

    assert result == expected_key
    mock_boto_client.assert_called_once_with(
        "s3",
        aws_access_key_id="xxx",
        aws_secret_access_key="xxx",
        region_name="us-east-1",
    )
    mock_s3.put_object.assert_called_once_with(
        Bucket="test-bucket",
        Key=expected_key,
        Body=b"raw evidence content",
    )


# 6. Non-retryable AWS ClientError
@pytest.mark.parametrize(
    "error_code", ["AccessDenied", "NoSuchBucket", "InvalidAccessKeyId"]
)
@patch("trellix_dlp.client.boto3.client")
def test_upload_evidence_non_retryable_client_error(
    mock_boto_client, aws_client, error_code
):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.put_object.side_effect = make_client_error(error_code)

    with pytest.raises(RuntimeError, match="AWS S3 upload failed"):
        aws_client.upload_evidence_to_s3(
            "incident-123", "evidence.jpg", b"test evidence"
        )


# 7. Retryable AWS errors retry three times
@pytest.mark.parametrize(
    "error_code",
    ["429", "500", "502", "503", "504", "RequestTimeout", "SlowDown"],
)
@patch("trellix_dlp.client.boto3.client")
def test_upload_evidence_retryable_client_errors(
    mock_boto_client, aws_client, error_code, monkeypatch
):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.put_object.side_effect = make_client_error(error_code)

    monkeypatch.setattr(
        aws_client.upload_evidence_to_s3.retry,
        "sleep",
        lambda _: None,
    )

    with pytest.raises(RetryableError, match=error_code):
        aws_client.upload_evidence_to_s3(
            "incident-123", "evidence.jpg", b"test evidence"
        )

    assert mock_s3.put_object.call_count == 3


# 8. Other BotoCoreError is retryable
@patch("trellix_dlp.client.boto3.client")
def test_upload_evidence_botocore_error(mock_boto_client, aws_client, monkeypatch):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.put_object.side_effect = BotoCoreError()

    monkeypatch.setattr(
        aws_client.upload_evidence_to_s3.retry,
        "sleep",
        lambda _: None,
    )

    with pytest.raises(RetryableError, match="AWS S3 error"):
        aws_client.upload_evidence_to_s3(
            "incident-123", "evidence.jpg", b"test evidence"
        )

    assert mock_s3.put_object.call_count == 3


# 9. Unexpected error becomes RuntimeError
@patch("trellix_dlp.client.boto3.client")
def test_upload_evidence_unexpected_error(mock_boto_client, aws_client):
    mock_boto_client.side_effect = ValueError("Unexpected failure")

    with pytest.raises(
        RuntimeError,
        match="Error while uploading evidence to S3",
    ):
        aws_client.upload_evidence_to_s3(
            "incident-123", "evidence.jpg", b"test evidence"
        )
