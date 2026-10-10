"""
This module defines custom exception types used across the Trellix DLP SDK.
"""


class RetryableError(Exception):
    """
    Raised for transient Trellix ePO errors that are safe to retry
    automatically (e.g. HTTP 5xx responses, HTTP 429, or network
    connection failures). Consumed internally by @retry decorators --
    callers of the SDK should not need to catch this directly.
    """
