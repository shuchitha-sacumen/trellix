import boto3
from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.models import TrellixAuthenticationModels, TrellixAWSCredentialsModels 
# aws_access_key = "xxx"
# aws_secret_key = "H3GBYr"
# aws_region = "us-east-1"
# bucket_name = "trellix-endpoint-test"

# s3 = boto3.client(
#     "s3",
#     aws_access_key_id=aws_access_key,
#     aws_secret_access_key=aws_secret_key,
#     region_name=aws_region,
# )

# try:
#     response = s3.head_bucket(
#         Bucket=bucket_name,
#     )

#     print("S3 connection successful")
#     print(f"Bucket: {bucket_name}")
#     print(f"Region: {aws_region}")

# except Exception as e:
#     print("S3 connection failed")
#     print(f"{type(e).__name__}: {e}")


# def test_upload_evidence_to_s3():
#     authentication = TrellixAuthenticationModels(
#         server_url="https://10.10.10:8443",
#         username="xxx",
#         password="yyy",
#     )

#     aws_credentials = TrellixAWSCredentialsModels(
#         aws_access_key = "xxx",
#         aws_secret_key = "yyy",
#         aws_region = "us-east-1",
#         bucket_name = "trellix-endpoint-test"
#     )

#     client = TrellixDataProtection(
#         authentication=authentication,
#         verify_ssl=False,
#         aws_credentials=aws_credentials,
#     )

#     evidence = b"test trellix dlp evidence"

#     object_key = client.upload_evidence_to_s3(
#         incident_id="test-123",
#         file_name="test-evidence.txt",
#         evidence=evidence,
#     )

#     assert object_key == (
#         "trellix-dlp/incidents/"
#         "test-123/test-evidence.txt"
#     )

def test_fetch_evidence_from_s3():

    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10:8443",
        username="xx",
        password="asxd"
    )

    aws_credentials = TrellixAWSCredentialsModels(
        aws_access_key = "xxx",
        aws_secret_key = "Hk",
        aws_region = "us-east-1",
        bucket_name = "trellix-endpoint-test"
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
        aws_credentials=aws_credentials,
    )

    evidence = client.fetch_evidence_from_s3(
        incident_id="test-trellix-incident",
        file_name="ScreenCapture.jpg",
    )

    assert isinstance(evidence, bytes)
    assert evidence