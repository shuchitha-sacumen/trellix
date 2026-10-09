import vcr

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.models import (
    TrellixAuthenticationModels,
    TrellixAWSCredentialsModels,
    TrellixEPOAssignedPolicyModels,
    TrellixIncidentIdsModels,
    TrellixIncidentModels,
    TrellixPolicyModels,
    TrellixRuleSetModels,
)

my_vcr = vcr.VCR(
    cassette_library_dir="tests/cassettes",
    record_mode="once",
    match_on=["method", "uri", "query"],
    decode_compressed_response=True,
)


@my_vcr.use_cassette("fetch_incident_ids.yml")
def test_fetch_incident_ids():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10",
        username="xxx",
        password="Sxxx",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    result = client.fetch_incident_ids(
        start_time=0,
        incident_nature=1,
    )

    assert isinstance(result, TrellixIncidentIdsModels)
    assert isinstance(result.incident_ids, list)
    assert isinstance(result.end_time, str)


@my_vcr.use_cassette("fetch_incident_details.yml")
def test_fetch_incident_details():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10",
        username="xxx",
        password="Sxxx",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    incident_id = 1993
    incident_details = client.fetch_incident_details(
        incident_id=incident_id,
        incident_nature=1,
    )

    assert isinstance(incident_id, int)
    assert isinstance(incident_details, TrellixIncidentModels)


@my_vcr.use_cassette("fetch_rulesets.yml")
def test_fetch_rulesets():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10",
        username="xxx",
        password="Sxxx",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    top = 5
    last_ruleset_id = None
    all_rulesets = []

    while True:
        page = client.fetch_rulesets(
            top=top,
            last_ruleset_id=last_ruleset_id,
        )

        assert isinstance(page, list)

        if not page:
            break

        assert isinstance(page[0], TrellixRuleSetModels)
        assert len(page) <= top

        all_rulesets.extend(page)

        last_ruleset_id = page[-1].rule_set_id

    assert all_rulesets


@my_vcr.use_cassette("find_policy.yml")
def test_find_policies():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10",
        username="xxx",
        password="Sxxx",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )
    searchText = "UDLPSRVR2013"
    policies = client.find_policies(searchText=searchText)

    assert isinstance(policies, list)
    assert isinstance(policies[0], TrellixPolicyModels)


@my_vcr.use_cassette("fetch_epo_assigned_policies.yml")
def test_fetch_epo_assigned_policies():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10",
        username="xxx",
        password="Sxxx",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    top = 5
    last_policy_object_id = None
    all_policies = []

    while True:
        page = client.fetch_epo_assigned_policies(
            top=top,
            last_policy_object_id=last_policy_object_id,
        )

        assert isinstance(page, list)

        # No more records
        if not page:
            break

        assert isinstance(
            page[0],
            TrellixEPOAssignedPolicyModels,
        )

        assert len(page) <= top

        # Verify page is sorted by PolicyObjectID
        assert page == sorted(
            page,
            key=lambda policy: policy.policy_object_id,
        )

        # Verify there are no duplicate records
        page_ids = {policy.policy_object_id for policy in page}

        existing_ids = {policy.policy_object_id for policy in all_policies}

        assert page_ids.isdisjoint(existing_ids)

        # Add current page to all fetched policies
        all_policies.extend(page)

        # Get last ID for the next page
        last_policy_object_id = page[-1].policy_object_id

    assert all_policies


@my_vcr.use_cassette("fetch_evidence.yml")
def test_fetch_evidence():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10",
        username="xxx",
        password="Sxxx",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    file_location = (
        r"\\EPO-SERVER\DLP-Evidence\B7\AF"
        r"\{46B7AF60-35E1-4966-FFBD-824E59ACB706}.jpg.dlpenc"
    )

    evidence = client.fetch_evidence(
        file_location=file_location,
    )

    # Evidence should be returned as raw bytes
    assert isinstance(evidence, bytes)

    # Evidence should not be empty
    assert evidence


def test_fetch_and_upload_evidence_to_s3():

    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10",
        username="xxx",
        password="Sxxx",
    )

    aws_credentials = TrellixAWSCredentialsModels(
        aws_access_key="xxx",
        aws_secret_key="yyyr",
        aws_region="us-east-1",
        bucket_name="trellix-endpoint-test",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
        aws_credentials=aws_credentials,
    )

    file_location = (
        r"\\EPO-SERVER\DLP-Evidence\B7\AF"
        r"\{46B7AF60-35E1-4966-FFBD-824E59ACB706}.jpg.dlpenc"
    )

    # VCR is used only for the Trellix API call
    with my_vcr.use_cassette("fetch_evidence.yml"):
        evidence = client.fetch_evidence(
            file_location=file_location,
        )

    # Confirm Trellix returned raw bytes
    assert isinstance(evidence, bytes)
    assert evidence

    # This happens OUTSIDE VCR.
    # Therefore boto3 makes the real AWS request.
    object_key = client.upload_evidence_to_s3(
        incident_id="test-trellix-incident",
        file_name="ScreenCapture.jpg",
        evidence=evidence,
    )

    assert object_key == (
        "trellix-dlp/incidents/" "test-trellix-incident/ScreenCapture.jpg"
    )


def test_fetch_upload_and_download_evidence():

    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10",
        username="xxx",
        password="Sxxx",
    )

    aws_credentials = TrellixAWSCredentialsModels(
        aws_access_key="xxx",
        aws_secret_key="yyyr",
        aws_region="us-east-1",
        bucket_name="trellix-endpoint-test",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
        aws_credentials=aws_credentials,
    )

    file_location = (
        r"\\EPO-SERVER\DLP-Evidence\B7\AF"
        r"\{46B7AF60-35E1-4966-FFBD-824E59ACB706}.jpg.dlpenc"
    )

    # ---------------------------------------------------------
    # Fetch evidence from Trellix using VCR
    # ---------------------------------------------------------
    with my_vcr.use_cassette("fetch_evidence.yml"):
        trellix_evidence = client.fetch_evidence(
            file_location=file_location,
        )

    assert isinstance(trellix_evidence, bytes)
    assert trellix_evidence

    # ---------------------------------------------------------
    # Upload the actual Trellix evidence to S3
    # ---------------------------------------------------------
    object_key = client.upload_evidence_to_s3(
        incident_id="test-trellix-incident",
        file_name="ScreenCapture.jpg",
        evidence=trellix_evidence,
    )

    assert object_key == (
        "trellix-dlp/incidents/" "test-trellix-incident/ScreenCapture.jpg"
    )

    # ---------------------------------------------------------
    # Fetch the evidence back from S3
    # ---------------------------------------------------------
    s3_evidence = client.fetch_evidence_from_s3(
        incident_id="test-trellix-incident",
        file_name="ScreenCapture.jpg",
    )

    assert isinstance(s3_evidence, bytes)
    assert s3_evidence

    # ---------------------------------------------------------
    # Verify evidence was preserved
    # ---------------------------------------------------------
    assert trellix_evidence == s3_evidence
