import boto3


def get_boto3_session(profile=None):
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()