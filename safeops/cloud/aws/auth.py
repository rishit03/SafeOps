import os
from botocore.exceptions import ProfileNotFound

from safeops.cloud.aws.session import get_boto3_session


def aws_credentials_exist():
    aws_path = os.path.expanduser("~/.aws/credentials")
    return os.path.exists(aws_path)


def validate_aws_setup(profile=None):
    if not aws_credentials_exist():
        return {
            "success": False,
            "error": "AWS credentials not found. Configure AWS CLI first using 'aws configure'."
        }

    try:
        get_boto3_session(profile=profile)
    except ProfileNotFound:
        return {
            "success": False,
            "error": f"AWS profile '{profile}' not found."
        }

    return {
        "success": True,
        "error": None
    }