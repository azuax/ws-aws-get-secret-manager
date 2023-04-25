#!/usr/bin/env python3

import boto3
import base64
import json
from botocore.exceptions import ClientError


def get_secret(profile_name=None, secret_name=None, region_name = "us-east-1"):

    # Create a Secrets Manager client
    if profile_name:
        session = boto3.session.Session(profile_name=profile_name)
    else:
        session = boto3.session.Session()

    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            raise e
        print(e)
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            return get_secret_value_response['SecretString']
        else:
            return base64.b64decode(get_secret_value_response['SecretBinary'])
    

if __name__ == '__main__':
    try:
        secret_key = 'API_KEY'
        profile_name = input('Please enter the profile name (None): ')
        secret_name = input('Please enter the secret you want (test/api-key): ') or 'test/api-key'
        secret = get_secret(profile_name=profile_name, secret_name=secret_name)
        j_secret = json.loads(secret)
    except Exception as e:
        print(e)
        exit(1)
    else:
        print("Obtained secret: ", j_secret[secret_key])
