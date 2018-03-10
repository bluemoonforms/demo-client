#!/bin/bash

if [ -z "$ENVIRONMENT" ]; then
    ENVIRONMENT='qa';
fi

# Check that the environment variable has been set correctly
if [ -z "$SECRETS_BUCKET_NAME" ]; then
  echo >&2 'error: missing SECRETS_BUCKET_NAME environment variable, default to env variables.'
else
    # Load the S3 secrets file contents into the environment variables
    eval $(aws s3 cp s3://${SECRETS_BUCKET_NAME}/demo_client/${ENVIRONMENT}/secrets.txt - | sed 's/^/export /')
fi

# Call the entry-point script
/entrypoint.sh "$@"
