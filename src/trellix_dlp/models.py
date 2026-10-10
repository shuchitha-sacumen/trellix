"""
This module defines Pydantic models for handling Trellix Data Loss Prevention
(DLP) and ePolicy Orchestrator (ePO) API responses.

These models are structured to represent Trellix DLP authentication,
policies, rule sets, incident IDs, detailed incidents, and evidence information.
They provide a type-safe and structured way to work with Trellix DLP API responses.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# Authentication
class TrellixAuthenticationModels(BaseModel):
    """
    Represents the authentication details required for Trellix ePO API access.

    Attributes:
        server_url (str): The URL of the Trellix ePO On-Prem server.
        username (str): The username used to authenticate with the ePO server.
        password (str): The password used to authenticate with the ePO server.
    """

    server_url: str
    username: str
    password: str


class TrellixAWSCredentialsModels(BaseModel):
    """
    Represents the AWS credentials and S3 configuration
    required for Trellix DLP evidence storage.

    Attributes:
        aws_access_key (str): AWS access key ID.
        aws_secret_key (str): AWS secret access key.
        aws_region (str): AWS region where the S3 bucket is located.
        bucket_name (str): Name of the S3 bucket.
    """

    aws_access_key: str
    aws_secret_key: str
    aws_region: str
    bucket_name: str


# EPO Assigned Policy
class TrellixEPOAssignedPolicyModels(BaseModel):
    """
    Represents an EPO assigned policy returned by the Trellix ePO server.

    Attributes:
        node_name: Name of the node to which the policy is assigned.
        policy_object_id: Object ID of the assigned policy.
        policy_desc: Description of the policy.
        feature_text_id: Feature text ID of the policy.
        category_text_id: Category text ID of the policy.
        up_to_date: Whether the assigned policy is up to date.
    """

    node_name: str
    policy_object_id: int
    policy_desc: str
    feature_text_id: str
    category_text_id: int
    up_to_date: bool


# Find policies
class TrellixPolicyModels(BaseModel):
    """
    Represents a DLP policy returned by the Trellix ePO API.

    Attributes:
        product_id (str): Identifier of the product associated with the policy.
        feature_name (str): Name of the feature associated with the policy.
        type_name (str): Type of the policy object.
        object_name (str): Name of the policy.
        type_id (int): Identifier of the policy object type.
        feature_id (str): Identifier of the feature associated with the policy.
        object_id (int): Unique identifier of the policy object.
        product_name (str): Name and version of the associated product.
        object_notes (str): Notes associated with the policy.
    """

    product_id: str = Field(alias="productId")
    feature_name: str = Field(alias="featureName")
    type_name: str = Field(alias="typeName")
    object_name: str = Field(alias="objectName")
    type_id: int = Field(alias="typeId")
    feature_id: str = Field(alias="featureId")
    object_id: int = Field(alias="objectId")
    product_name: str = Field(alias="productName")
    object_notes: str = Field(alias="objectNotes")


# Rule Set
class TrellixRuleSetModels(BaseModel):
    """
    Represents a DLP rule set returned by the Trellix ePO API.

    Attributes:
        rule_set_id (str): Unique identifier of the rule set.
        catalog_id (str): Identifier of the catalog associated with the rule set.
        name (str): Name of the rule set.
        description (str): Description of the rule set.
        enabled (int): Indicates whether the rule set is enabled.
        owner (int): Identifier of the rule set owner.
        last_modifier (int): Identifier of the user who last modified the rule set.
        modification_time (str): Date and time when the rule set was last modified.
    """

    rule_set_id: str = Field(alias="UDLP_RuleSets.RuleSetID")
    catalog_id: str = Field(alias="UDLP_RuleSets.CatalogID")
    name: str = Field(alias="UDLP_RuleSets.Name")
    description: str = Field(alias="UDLP_RuleSets.Description")
    enabled: int = Field(alias="UDLP_RuleSets.Enabled")
    owner: int = Field(alias="UDLP_RuleSets.Owner")
    last_modifier: int = Field(alias="UDLP_RuleSets.LastModifier")
    modification_time: str = Field(alias="UDLP_RuleSets.ModificationTime")


# Incident IDs
class TrellixIncidentIdsModels(BaseModel):
    """
    Represents the incident IDs response from the Trellix DLP API.

    Attributes:
        incident_ids (List[str]): List of DLP incident IDs.
        end_time (str): End time timestamp returned by the API for the incident ID query.
    """

    incident_ids: List[str]
    end_time: str


# Incident Details
class TrellixGeneralDetailsModels(BaseModel):
    """
    Represents the general details of a Trellix DLP incident.

    Attributes:
        incident_id (str): Unique identifier of the DLP incident.
        occurred_utc (str): Time when the incident occurred in UTC.
        occurred_endpoint (str): Time when the incident occurred on the endpoint.
        incident_type (str): Type of the DLP incident.
        actual_action (str): Action actually taken for the incident.
        failure_reason (str): Reason for any action failure.
        expected_action (str): Action expected for the incident.
        severity (str): Severity of the incident.
        status (str): Current status of the incident.
        resolution (str): Resolution status of the incident.
        reviewer (str): Reviewer assigned to the incident.
        labels (List[Any]): Labels associated with the incident.
    """

    incident_id: str = Field(alias="incidentID")
    occurred_utc: str = Field(alias="occurred_UTC")
    occurred_endpoint: str = Field(alias="occurred_Endpoint")
    incident_type: str = Field(alias="incidentType")
    actual_action: str = Field(alias="actualAction")
    failure_reason: str = Field(alias="failureReason")
    expected_action: str = Field(alias="expectedAction")
    severity: str
    status: str
    resolution: str
    reviewer: str
    labels: List[Any]


class TrellixEndpointDetailsModels(BaseModel):
    """
    Represents endpoint details associated with a Trellix DLP incident.

    Attributes:
        computer_name (str): Name of the computer where the incident occurred.
        computer_ip (str): IP address of the computer.
        connectivity_state (str): Connectivity state of the endpoint.
        source_application (str): Application associated with the incident.
    """

    computer_name: str = Field(alias="computerName")
    computer_ip: str = Field(alias="computerIP")
    connectivity_state: str = Field(alias="connectivityState")
    source_application: str = Field(alias="sourceApplication")


class TrellixUserDetailsModels(BaseModel):
    """
    Represents user details associated with a Trellix DLP incident.

    Attributes:
        user_principal_name (str): User principal name.
        user_account (str): User account associated with the incident.
        user_email (str): Email address of the user.
        user_ou (str): Organizational unit of the user.
        user_groups (str): Groups associated with the user.
        user_name (Optional[str]): Name of the user.
        user_title (Optional[str]): Job title of the user.
        user_department (Optional[str]): Department of the user.
        user_manager (Optional[str]): Manager of the user.
        user_id (Optional[str]): Unique identifier of the user.
    """

    user_principal_name: str = Field(alias="userPrincipalName")
    user_account: str = Field(alias="userAccount")
    user_email: str = Field(alias="userEmail")
    user_ou: str = Field(alias="userOU")
    user_groups: str = Field(alias="userGroups")
    user_name: Optional[str] = Field(default=None, alias="userName")
    user_title: Optional[str] = Field(default=None, alias="userTitle")
    user_department: Optional[str] = Field(default=None, alias="userDepartment")
    user_manager: Optional[str] = Field(default=None, alias="userManager")
    user_id: Optional[str] = Field(default=None, alias="userId")


class TrellixReportingProductModels(BaseModel):
    """
    Represents the reporting product details associated with a Trellix DLP incident.

    Attributes:
        reporting_product (str): Name of the reporting DLP product.
        product_version (str): Version of the reporting product.
        policy_name (str): DLP policy associated with the incident.
        appliance_ip (str): IP address of the reporting appliance.
        appliance_host_name (str): Host name of the reporting appliance.
    """

    reporting_product: str = Field(alias="reportingProduct")
    product_version: str = Field(alias="productVersion")
    policy_name: str = Field(alias="policyName")
    appliance_ip: str = Field(alias="applianceIP")
    appliance_host_name: str = Field(alias="applianceHostName")


class TrellixEvidenceModels(BaseModel):
    """
    Represents evidence associated with a Trellix DLP incident.

    Attributes:
        evidence_name (str): Name of the evidence file.
        evidence_location (str): Relative location of the evidence file.
        hit_highlight_location (str): Location of the highlighted match.
        evidence_prefix (str): Network share path where the evidence is stored.
        item_type (str): Type of evidence item.
        file_size_kb (str): Size of the evidence file in KB.
        match_count (str): Number of matches in the evidence.
        unique_match_count (str): Number of unique matches in the evidence.
        short_match_string (str): Short match string.
        unique_match_strings (str): Unique match strings.
        classifications (str): Classifications associated with the evidence.
        path (str): Evidence path.
        sha1 (str): SHA1 hash of the evidence file.
        matched_fingerprints (List[Any]): Fingerprints matched by the evidence.
    """

    evidence_name: str = Field(alias="evidenceName")
    evidence_location: str = Field(alias="evidenceLocation")
    hit_highlight_location: str = Field(alias="hitHighlightLocation")
    evidence_prefix: str = Field(alias="evidencePrefix")
    item_type: str = Field(alias="itemType")
    file_size_kb: str = Field(alias="fileSize_KB")
    match_count: str = Field(alias="matchCount")
    unique_match_count: str = Field(alias="uniqueMatchCount")
    short_match_string: str = Field(alias="shortMatchString")
    unique_match_strings: str = Field(alias="uniqueMatchStrings")
    classifications: str
    path: str
    sha1: str = Field(alias="sHA1")
    matched_fingerprints: List[Any] = Field(alias="matchedFingerprints")


class TrellixRuleModels(BaseModel):
    """
    Represents a DLP rule associated with a Trellix DLP incident.

    Attributes:
        rule_set_name (str): Name of the rule set.
        rule_name (str): Name of the DLP rule.
        configured_action (str): Action configured for the rule.
        severity (str): Severity of the rule.
        action_triggered (str): Action triggered by the rule.
        modification_date (str): Date when the rule was last modified.
    """

    rule_set_name: str = Field(alias="ruleSetName")
    rule_name: str = Field(alias="ruleName")
    configured_action: str = Field(alias="configuredAction")
    severity: str
    action_triggered: str = Field(alias="actionTriggered")
    modification_date: str = Field(alias="modificationDate")


class TrellixIncidentModels(BaseModel):
    """
    Represents detailed information for a Trellix DLP incident.

    Attributes:
        general_details (TrellixGeneralDetailsModels): General incident details.
        endpoint_details (TrellixEndpointDetailsModels): Endpoint details.
        event_user_details (TrellixUserDetailsModels): User details at the time of the event.
        last_updated_user_details (TrellixUserDetailsModels):
            Details of the user who last updated the incident.
        reporting_product (TrellixReportingProductModels): Reporting product details.
        total_match_count (str): Total number of matches associated with the incident.
        total_content_size_kb (str): Total content size in KB.
        additional_information (Dict[str, Any]): Additional incident information.
        access_control_list (List[Any]): Access control information.
        custom_attributes (Dict[str, Any]): Custom attributes associated with the incident.
        evidences (List[TrellixEvidenceModels]): Evidence associated with the incident.
        rules (List[TrellixRuleModels]): Rules associated with the incident.
        classifications (List[Any]): Classifications associated with the incident.
        stakeholders (List[Any]): Stakeholders associated with the incident.
        audit_logs (List[Any]): Audit logs associated with the incident.
        comments (List[Any]): Comments associated with the incident.
        cases (List[Any]): Cases associated with the incident.
    """

    general_details: TrellixGeneralDetailsModels = Field(alias="generalDetails")
    endpoint_details: TrellixEndpointDetailsModels = Field(alias="endpointDetails")
    event_user_details: TrellixUserDetailsModels = Field(alias="eventUserDetails")
    last_updated_user_details: TrellixUserDetailsModels = Field(
        alias="lastUpdatedUserDetails"
    )
    reporting_product: TrellixReportingProductModels = Field(alias="reportingProduct")
    total_match_count: str = Field(alias="totalMatchCount")
    total_content_size_kb: str = Field(alias="totalContentSize_KB")
    additional_information: Dict[str, Any] = Field(alias="additionalInformation")
    access_control_list: List[Any] = Field(alias="accessControlList")
    custom_attributes: Dict[str, Any] = Field(alias="customAttributes")
    evidences: List[TrellixEvidenceModels]
    rules: List[TrellixRuleModels]
    classifications: List[Any]
    stakeholders: List[Any]
    audit_logs: List[Any] = Field(alias="auditLogs")
    comments: List[Any]
    cases: List[Any]
