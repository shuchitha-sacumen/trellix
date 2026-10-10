import vcr

from trellix_dlp.auth import TrellixDLPAuth
from trellix_dlp.models import TrellixAuthenticationModels

my_vcr = vcr.VCR(
    cassette_library_dir="tests/cassettes",
    record_mode="once",
    match_on=["method", "uri", "query"],
)


@my_vcr.use_cassette("test_connection.yml")
def test_connection():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10:8443",
        username="test_user",
        password="DummyPass@2026",
    )

    auth = TrellixDLPAuth(authentication)

    result = auth.test_connection()

    assert result is True
