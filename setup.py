from setuptools import find_packages, setup

setup(
    name="trellix_dlp_sdk",
    version="1.0.0",
    description="A Python SDK for interacting with Trellix DLP On-Prem",
    author="sacumen",
    url="https://github.com/",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=[
        "pydantic>=2.11.0",
        "requests>=2.31.0",
        "retry>=0.9.2",
        "boto3>=1.39.10",
        "vcrpy>=5.1.0",
        "pytest>=8.0.0",
    ],
)