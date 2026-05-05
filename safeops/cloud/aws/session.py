import boto3


def get_boto3_session(profile=None, role_arn=None, session_name="safeops-session"):
    base_session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    if not role_arn:
        return base_session

    sts = base_session.client("sts")
    assumed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )

    creds = assumed["Credentials"]

    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )