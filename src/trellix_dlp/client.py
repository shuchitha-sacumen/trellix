"""
This module implements the Trellix DLP On-Prem (ePO) API client for
incident, policy, and evidence retrieval.
"""

import json
from typing import List
from urllib.parse import quote

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError
from requests.auth import HTTPBasicAuth
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .exceptions import RetryableError
from .models import (
    TrellixAuthenticationModels,
    TrellixAWSCredentialsModels,
    TrellixEPOAssignedPolicyModels,
    TrellixIncidentIdsModels,
    TrellixIncidentModels,
    TrellixPolicyModels,
    TrellixRuleSetModels,
)


class TrellixDataProtection:
    """
    Trellix DLP (ePO On-Prem) Data Protection API client.

    :param authentication: Trellix ePO server URL and Basic Auth credentials.
    :param verify_ssl: Whether to verify the ePO server's TLS certificate.
        Defaults to False for sandbox/self-signed environments.
    """

    def __init__(
        self,
        authentication: TrellixAuthenticationModels,
        verify_ssl: bool = False,
        aws_credentials: TrellixAWSCredentialsModels | None = None,
    ):
        self.authentication = authentication
        self.verify_ssl = verify_ssl
        self.aws_credentials = aws_credentials

    
    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def fetch_incident_ids(
        self,
        start_time: int | None = None,
        incident_nature: int | None = None,
    ) -> TrellixIncidentIdsModels:
        """
        Fetch a single page of Trellix DLP incident IDs.

        Trellix returns at most 1000 incident IDs per call. The response's
        end_time represents the occurred-time of the last incident in the
        current page. If end_time is not "null", the caller can use that
        value as the start_time for the next request.

        Args:
            start_time:
                Epoch time in milliseconds. Optional. When provided, incidents
                occurring on or after this time are returned.

            incident_nature:
                Optional incident data vector:
                    1 = data-in-use/motion
                    2 = reserved - Endpoint Discovery
                    3 = data-at-rest - Network

        Returns:
            TrellixIncidentIdsModels:
                Parsed incident IDs and end_time cursor.

        Raises:
            ValueError:
                If start_time or incident_nature has an invalid type/value.

            RuntimeError:
                On non-retryable HTTP, timeout, parsing, or request errors.

            RetryableError:
                On HTTP 5xx, HTTP 429, or connection errors.
                These are handled internally by tenacity.
        """

        # ---------------------------------------------------------
        # Validate start_time
        # ---------------------------------------------------------
        if start_time is not None:
            if isinstance(start_time, bool) or not isinstance(start_time, int):
                raise ValueError(
                    "start_time must be an integer epoch milliseconds value"
                )

            if start_time < 0:
                raise ValueError("start_time must be greater than or equal to zero")

        # ---------------------------------------------------------
        # Validate incident_nature
        # ---------------------------------------------------------
        if incident_nature is not None:
            if isinstance(incident_nature, bool) or not isinstance(
                incident_nature, int
            ):
                raise ValueError("incident_nature must be an integer")

            if incident_nature not in (1, 2, 3):
                raise ValueError(
                    "incident_nature must be 1 (data-in-use/motion), "
                    "2 (reserved - Endpoint Discovery), "
                    "or 3 (data-at-rest - Network)"
                )

        url = f"{self.authentication.server_url.rstrip('/')}" "/rest/dlp/incidents/ids"

        # ---------------------------------------------------------
        # Build query parameters
        #
        # Only include parameters that were actually provided.
        # This allows Trellix itself to return the appropriate
        # 400 error when required parameters are missing.
        # ---------------------------------------------------------
        params = {}

        if start_time is not None:
            params["startTime"] = start_time

        if incident_nature is not None:
            params["incidentNature"] = incident_nature

        try:
            # -----------------------------------------------------
            # Make API request
            # -----------------------------------------------------
            response = requests.get(
                url=url,
                params=params,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=10,
                verify=self.verify_ssl,
            )

            # -----------------------------------------------------
            # Raise HTTPError for 4xx/5xx responses
            # -----------------------------------------------------
            response.raise_for_status()

            # -----------------------------------------------------
            # Parse JSON response
            # -----------------------------------------------------
            data = response.json()

            # Trellix returns endTime as "null" when there are no
            # more incidents. Convert the value to string so that
            # the model consistently receives "null".
            return TrellixIncidentIdsModels(
                incident_ids=data.get("incidentIds", []),
                end_time=str(data.get("endTime", "null")),
            )

        # ---------------------------------------------------------
        # HTTP errors
        # ---------------------------------------------------------
        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc
        # ---------------------------------------------------------
        # Timeout
        # ---------------------------------------------------------
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch incident IDs."
            ) from exc
        # ---------------------------------------------------------
        # Connection error
        # ---------------------------------------------------------
        except requests.exceptions.ConnectionError as exc:
            raise RetryableError("ConnectionError: Unable to connect") from exc

        # ---------------------------------------------------------
        # Pydantic response validation error
        # ---------------------------------------------------------
        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        # ---------------------------------------------------------
        # Other requests errors
        # ---------------------------------------------------------
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

        # ---------------------------------------------------------
        # Unexpected errors
        # ---------------------------------------------------------
        except Exception as err:
            raise err

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def fetch_incident_details(
        self,
        incident_id: int,
        incident_nature: int | None = None,
    ) -> TrellixIncidentModels:
        """
        Fetch detailed information for a specific Trellix DLP incident.

        Args:
            incident_id:
                Numeric ID of the DLP incident.

            incident_nature:
                Optional data vector of the incident.

                1 = Data-in-use / Data-in-motion
                2 = Data-at-rest / Endpoint
                3 = Data-at-rest / Network

                If omitted, the request is sent without the
                incidentNature parameter so that Trellix returns
                its native API validation error.

        Returns:
            TrellixIncidentModels:
                Parsed details of the requested incident.

        Raises:
            ValueError:
                If incident_id or incident_nature has an invalid value.

            RuntimeError:
                On non-retryable HTTP errors, timeout, response parsing,
                or other request errors.

            RetryableError:
                On HTTP 429, HTTP 5xx, or connection errors.
        """

        # ---------------------------------------------------------
        # Validate incident_id
        # ---------------------------------------------------------
        if incident_id is None:
            raise ValueError("incident_id must not be null")

        if isinstance(incident_id, bool) or not isinstance(incident_id, int):
            raise ValueError("incident_id must be an integer")

        if incident_id < 0:
            raise ValueError("incident_id must be greater than or equal to zero")

        # ---------------------------------------------------------
        # Validate incident_nature only when provided
        # ---------------------------------------------------------
        if incident_nature is not None:

            if isinstance(incident_nature, bool) or not isinstance(
                incident_nature, int
            ):
                raise ValueError("incident_nature must be an integer")

            if incident_nature not in (1, 2, 3):
                raise ValueError("incident_nature must be one of 1, 2, or 3")

        # ---------------------------------------------------------
        # Build URL
        # ---------------------------------------------------------
        url = (
            f"{self.authentication.server_url.rstrip('/')}"
            f"/rest/dlp/incidents/{incident_id}"
        )

        # ---------------------------------------------------------
        # Build query parameters
        #
        # If incident_nature is None, don't add the parameter.
        # This allows Trellix to return its native 400 response.
        # ---------------------------------------------------------
        params = {}

        if incident_nature is not None:
            params["incidentNature"] = incident_nature

        try:
            # -----------------------------------------------------
            # Make API request
            # -----------------------------------------------------
            response = requests.get(
                url=url,
                params=params,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=10,
                verify=self.verify_ssl,
            )

            # -----------------------------------------------------
            # Raise HTTPError for 4xx/5xx
            # -----------------------------------------------------
            response.raise_for_status()

            # -----------------------------------------------------
            # Parse JSON response
            # -----------------------------------------------------
            incident_response = response.json()

            # -----------------------------------------------------
            # Convert API response into Pydantic model
            # -----------------------------------------------------
            return TrellixIncidentModels(**incident_response)

        # ---------------------------------------------------------
        # HTTP errors
        # ---------------------------------------------------------
        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc
        # ---------------------------------------------------------
        # Timeout
        # ---------------------------------------------------------
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to get incident details."
            ) from exc

        # ---------------------------------------------------------
        # Connection error
        # ---------------------------------------------------------
        except requests.exceptions.ConnectionError as exc:
            raise RetryableError("ConnectionError: Unable to connect") from exc

        # ---------------------------------------------------------
        # Pydantic / JSON parsing errors
        # ---------------------------------------------------------
        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        # ---------------------------------------------------------
        # Other requests errors
        # ---------------------------------------------------------
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

        # ---------------------------------------------------------
        # Unexpected errors
        # ---------------------------------------------------------
        except Exception as err:
            raise err

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def fetch_rulesets(
        self,
        top: int = 6,
        last_ruleset_id: str | None = None,
    ) -> List[TrellixRuleSetModels]:
        """
        Fetch DLP rule sets from the Trellix ePO server.

        Args:
            top (int): Maximum number of rule sets to fetch in one batch.
            last_ruleset_id (str | None): RuleSetID of the last rule set
                fetched from the previous batch.

        Returns:
            List[TrellixRuleSetModels]: Parsed DLP rule sets.

        Raises:
            RuntimeError: On HTTP, parsing, timeout, or request errors.
            RetryableError: On 5xx, 429, or connection errors.
        """

        url = (
            f"{self.authentication.server_url.rstrip('/')}" "/remote/core.executeQuery"
        )

        select = (
            f"(select (top {top}) "
            "UDLP_RuleSets.RuleSetID "
            "UDLP_RuleSets.CatalogID "
            "UDLP_RuleSets.Name "
            "UDLP_RuleSets.Description "
            "UDLP_RuleSets.Enabled "
            "UDLP_RuleSets.Owner "
            "UDLP_RuleSets.LastModifier "
            "UDLP_RuleSets.ModificationTime)"
        )

        params = {
            ":output": "json",
            "target": "UDLP_RuleSets",
            "select": select,
            "order": "(order (asc UDLP_RuleSets.RuleSetID))",
        }

        if last_ruleset_id is not None:
            params["where"] = f'(gt UDLP_RuleSets.RuleSetID "{last_ruleset_id}")'

        try:
            response = requests.get(
                url=url,
                params=params,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=10,
                verify=self.verify_ssl,
            )

            response.raise_for_status()
            text = response.text.strip()

            if text.startswith("ERROR:"):
                raise RuntimeError(f"ePO Remote Command returned an error: {text}")

            if text.startswith("OK:"):
                payload = text[len("OK:") :].strip()
            else:
                payload = text

            data = json.loads(payload) if payload else []

            return [TrellixRuleSetModels(**item) for item in data]

        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch incident IDs."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RetryableError(
                "ConnectionError: Unable to connect to Trellix ePO."
            ) from exc

        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

        except Exception as err:
            raise err

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def find_policies(
        self,
        searchText: str = "",
    ) -> List[TrellixPolicyModels]:
        """
        Fetch DLP policies from the Trellix ePO server.

        Returns:
            List[TrellixPolicyModels]: Parsed DLP policies.

        Raises:
            RuntimeError: On HTTP, parsing, timeout, or request errors.
            RetryableError: On 5xx, 429, or connection errors.
        """

        url = f"{self.authentication.server_url.rstrip('/')}" "/remote/policy.find"

        params = {
            ":output": "json",
            "searchText": searchText,
        }

        try:
            response = requests.get(
                url=url,
                params=params,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=10,
                verify=self.verify_ssl,
            )

            response.raise_for_status()
            text = response.text.strip()

            if text.startswith("ERROR:"):
                raise RuntimeError(f"ePO Remote Command returned an error: {text}")

            if text.startswith("OK:"):
                payload = text[len("OK:") :].strip()
            else:
                payload = text

            data = json.loads(payload) if payload else []

            return [TrellixPolicyModels(**item) for item in data]

        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch DLP policies."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RetryableError("ConnectionError: Unable to connect") from exc

        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

        except Exception as err:
            raise err

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def fetch_epo_assigned_policies(
        self,
        top: int = 5,
        last_policy_object_id: int | None = None,
    ) -> List[TrellixEPOAssignedPolicyModels]:
        """
        Fetch a page of EPO assigned policies from the Trellix ePO server.

        Args:
            top:
                Maximum number of records to return in the current page.

            last_policy_object_id:
                PolicyObjectID of the last record from the previous page.
                When provided, only records with a greater PolicyObjectID
                are returned.

        Returns:
            List[TrellixEPOAssignedPolicyModels]:
                Parsed EPO assigned policies.

        Raises:
            ValueError:
                If top or last_policy_object_id has an invalid type/value.

            RuntimeError:
                On non-retryable HTTP, timeout, parsing, or request errors.

            RetryableError:
                On HTTP 5xx, HTTP 429, or connection errors.
        """

        # ---------------------------------------------------------
        # Validate top
        # ---------------------------------------------------------
        if isinstance(top, bool) or not isinstance(top, int):
            raise ValueError("top must be an integer")

        if top <= 0:
            raise ValueError("top must be greater than zero")

        # ---------------------------------------------------------
        # Validate last_policy_object_id
        # ---------------------------------------------------------
        if last_policy_object_id is not None:
            if isinstance(last_policy_object_id, bool) or not isinstance(
                last_policy_object_id, int
            ):
                raise ValueError("last_policy_object_id must be an integer")

            if last_policy_object_id < 0:
                raise ValueError(
                    "last_policy_object_id must be greater than or equal to zero"
                )

        # ---------------------------------------------------------
        # Build URL
        # ---------------------------------------------------------
        url = (
            f"{self.authentication.server_url.rstrip('/')}" "/remote/core.executeQuery"
        )

        # ---------------------------------------------------------
        # Build select
        # ---------------------------------------------------------
        select = (
            f"(select (top {top}) "
            "EPOAssignedPolicy.NodeName "
            "EPOAssignedPolicy.PolicyObjectID "
            "EPOAssignedPolicy.PolicyDesc "
            "EPOAssignedPolicy.FeatureTextID "
            "EPOAssignedPolicy.CategoryTextID "
            "EPOAssignedPolicy.upToDate)"
        )

        # ---------------------------------------------------------
        # Build parameters
        # ---------------------------------------------------------
        params = {
            ":output": "json",
            "target": "EPOAssignedPolicy",
            "order": "(order (asc EPOAssignedPolicy.PolicyObjectID))",
            "select": select,
        }

        if last_policy_object_id is not None:
            params["where"] = (
                f"(gt EPOAssignedPolicy.PolicyObjectID " f"{last_policy_object_id})"
            )

        try:
            # -----------------------------------------------------
            # Make API request
            # -----------------------------------------------------
            response = requests.get(
                url=url,
                params=params,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=10,
                verify=self.verify_ssl,
            )

            # -----------------------------------------------------
            # Raise HTTPError for 4xx/5xx responses
            # -----------------------------------------------------
            response.raise_for_status()

            # -----------------------------------------------------
            # Parse response
            # -----------------------------------------------------
            text = response.text.strip()

            if text.startswith("ERROR:"):
                raise RuntimeError(f"ePO Remote Command returned an error: {text}")

            if text.startswith("OK:"):
                payload = text[len("OK:") :].strip()
            else:
                payload = text

            data = json.loads(payload) if payload else []

            # -----------------------------------------------------
            # Convert API response to Pydantic models
            # -----------------------------------------------------
            return [
                TrellixEPOAssignedPolicyModels(
                    node_name=item["EPOAssignedPolicy.NodeName"],
                    policy_object_id=item["EPOAssignedPolicy.PolicyObjectID"],
                    policy_desc=item["EPOAssignedPolicy.PolicyDesc"],
                    feature_text_id=item["EPOAssignedPolicy.FeatureTextID"],
                    category_text_id=item["EPOAssignedPolicy.CategoryTextID"],
                    up_to_date=item["EPOAssignedPolicy.upToDate"],
                )
                for item in data
            ]

        # ---------------------------------------------------------
        # HTTP errors
        # ---------------------------------------------------------
        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        # ---------------------------------------------------------
        # Timeout
        # ---------------------------------------------------------
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch epo assigned policies."
            ) from exc

        # ---------------------------------------------------------
        # Connection error
        # ---------------------------------------------------------
        except requests.exceptions.ConnectionError as exc:
            raise RetryableError("ConnectionError: Unable to connect") from exc

        # ---------------------------------------------------------
        # Pydantic / JSON validation
        # ---------------------------------------------------------
        except (KeyError, ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        # ---------------------------------------------------------
        # Other requests errors
        # ---------------------------------------------------------
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

        # ---------------------------------------------------------
        # Unexpected errors
        # ---------------------------------------------------------
        except Exception as err:
            raise err

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def fetch_evidence(
        self,
        file_location: str,
    ) -> bytes:
        """
        Fetch raw DLP evidence from the Trellix ePO server.

        Args:
            file_location:
                Network share path of the evidence file returned by
                the DLP incident details.

        Returns:
            bytes:
                Decrypted raw evidence content returned by the
                Trellix DLP REST API.

        Raises:
            ValueError:
                If file_location has an invalid type or is empty.

            RuntimeError:
                On non-retryable HTTP, timeout, parsing, or request errors.

            RetryableError:
                On HTTP 5xx, HTTP 429, or connection errors.
        """

        # ---------------------------------------------------------
        # Validate file_location
        # ---------------------------------------------------------
        if not isinstance(file_location, str):
            raise ValueError("file_location must be a string")

        if not file_location.strip():
            raise ValueError("file_location must not be empty")

        # ---------------------------------------------------------
        # URL-encode the network share path
        # ---------------------------------------------------------
        encoded_file_location = quote(
            file_location,
            safe="",
        )

        # ---------------------------------------------------------
        # Build URL
        # ---------------------------------------------------------
        url = (
            f"{self.authentication.server_url.rstrip('/')}"
            "/rest/dlp/event/evidence/get"
            f"?fileLocation={encoded_file_location}"
        )

        try:
            # -----------------------------------------------------
            # Make API request
            # -----------------------------------------------------
            response = requests.post(
                url=url,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=30,
                verify=self.verify_ssl,
            )

            # -----------------------------------------------------
            # Raise HTTPError for 4xx/5xx responses
            # -----------------------------------------------------
            response.raise_for_status()

            # -----------------------------------------------------
            # Return decrypted evidence as bytes
            # -----------------------------------------------------
            return response.content

        # ---------------------------------------------------------
        # HTTP errors
        # ---------------------------------------------------------
        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        # ---------------------------------------------------------
        # Timeout
        # ---------------------------------------------------------
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch DLP evidence."
            ) from exc
        # ---------------------------------------------------------
        # Connection error
        # ---------------------------------------------------------
        except requests.exceptions.ConnectionError as exc:
            raise RetryableError(
                "ConnectionError: Unable to connect to Trellix ePO"
            ) from exc

        # ---------------------------------------------------------
        # Other requests errors
        # ---------------------------------------------------------
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

        # ---------------------------------------------------------
        # Unexpected errors
        # ---------------------------------------------------------
        except Exception as err:
            raise err

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def upload_evidence_to_s3(
        self,
        incident_id: str,
        file_name: str,
        evidence: bytes,
    ) -> str:
        """
        Upload raw DLP evidence to the configured AWS S3 bucket.

        Args:
            incident_id:
                ID of the DLP incident associated with the evidence.

            file_name:
                Name of the evidence file.

            evidence:
                Raw evidence content as bytes.

        Returns:
            str:
                S3 object key of the uploaded evidence.

        Raises:
            ValueError:
                If input values are invalid.

            RuntimeError:
                If AWS credentials are not configured or the upload fails.

            RetryableError:
                If a retryable AWS error occurs.
        """

        # ---------------------------------------------------------
        # Validate AWS configuration
        # ---------------------------------------------------------
        if self.aws_credentials is None:
            raise RuntimeError("AWS credentials are required for S3 operations.")

        # ---------------------------------------------------------
        # Validate incident_id
        # ---------------------------------------------------------
        if not isinstance(incident_id, str):
            raise ValueError("incident_id must be a string")

        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")

        # ---------------------------------------------------------
        # Validate file_name
        # ---------------------------------------------------------
        if not isinstance(file_name, str):
            raise ValueError("file_name must be a string")

        if not file_name.strip():
            raise ValueError("file_name must not be empty")

        # ---------------------------------------------------------
        # Validate evidence
        # ---------------------------------------------------------
        if not isinstance(evidence, bytes):
            raise ValueError("evidence must be bytes")

        if not evidence:
            raise ValueError("evidence must not be empty")

        # ---------------------------------------------------------
        # Build S3 object key
        # ---------------------------------------------------------
        object_key = f"trellix-dlp/incidents/" f"{incident_id}/{file_name}"

        try:
            # -----------------------------------------------------
            # Create S3 client
            # -----------------------------------------------------
            s3 = boto3.client(
                "s3",
                aws_access_key_id=self.aws_credentials.aws_access_key,
                aws_secret_access_key=self.aws_credentials.aws_secret_key,
                region_name=self.aws_credentials.aws_region,
            )

            # -----------------------------------------------------
            # Upload evidence
            # -----------------------------------------------------
            s3.put_object(
                Bucket=self.aws_credentials.bucket_name,
                Key=object_key,
                Body=evidence,
            )

            return object_key

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")

            if error_code in {
                "429",
                "500",
                "502",
                "503",
                "504",
                "RequestTimeout",
                "SlowDown",
            }:
                raise RetryableError(f"{error_code}--{exc}") from exc

            raise RuntimeError(f"AWS S3 upload failed: {exc}") from exc

        except BotoCoreError as exc:
            raise RetryableError(f"AWS S3 error: {exc}") from exc

        except Exception as exc:
            raise RuntimeError(f"Error while uploading evidence to S3: {exc}") from exc

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def fetch_evidence_from_s3(
        self,
        incident_id: str,
        file_name: str,
    ) -> bytes:
        """
        Fetch raw evidence from the configured AWS S3 bucket.

        Args:
            incident_id:
                ID of the DLP incident associated with the evidence.

            file_name:
                Name of the evidence file.

        Returns:
            bytes:
                Raw evidence content retrieved from S3.

        Raises:
            ValueError:
                If incident_id or file_name is invalid.

            RuntimeError:
                If AWS credentials are not configured or the
                S3 operation fails.

            RetryableError:
                If a retryable AWS error occurs.
        """

        # ---------------------------------------------------------
        # Validate AWS configuration
        # ---------------------------------------------------------
        if self.aws_credentials is None:
            raise RuntimeError("AWS credentials are required for S3 operations.")

        # ---------------------------------------------------------
        # Validate incident_id
        # ---------------------------------------------------------
        if not isinstance(incident_id, str):
            raise ValueError("incident_id must be a string")

        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")

        # ---------------------------------------------------------
        # Validate file_name
        # ---------------------------------------------------------
        if not isinstance(file_name, str):
            raise ValueError("file_name must be a string")

        if not file_name.strip():
            raise ValueError("file_name must not be empty")

        # ---------------------------------------------------------
        # Build S3 object key
        # ---------------------------------------------------------
        object_key = f"trellix-dlp/incidents/" f"{incident_id}/{file_name}"

        try:
            # -----------------------------------------------------
            # Create S3 client
            # -----------------------------------------------------
            s3 = boto3.client(
                "s3",
                aws_access_key_id=self.aws_credentials.aws_access_key,
                aws_secret_access_key=self.aws_credentials.aws_secret_key,
                region_name=self.aws_credentials.aws_region,
            )

            # -----------------------------------------------------
            # Fetch evidence from S3
            # -----------------------------------------------------
            response = s3.get_object(
                Bucket=self.aws_credentials.bucket_name,
                Key=object_key,
            )

            # -----------------------------------------------------
            # Read object content
            # -----------------------------------------------------
            evidence = response["Body"].read()

            return evidence

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")

            if error_code in {
                "429",
                "500",
                "502",
                "503",
                "504",
                "RequestTimeout",
                "SlowDown",
            }:
                raise RetryableError(f"{error_code}--{exc}") from exc

            raise RuntimeError(f"AWS S3 fetch failed: {exc}") from exc

        except BotoCoreError as exc:
            raise RetryableError(f"AWS S3 error: {exc}") from exc

        except Exception as exc:
            raise RuntimeError(f"Error while fetching evidence from S3: {exc}") from exc
