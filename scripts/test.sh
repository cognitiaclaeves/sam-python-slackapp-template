#!/usr/bin/env bash

SECRETS_NAME="slack-helpdesk-creds"  # The name of the secret in secrets manager that stores
AWS_PROFILE="compeat-dev"  # Your AWS profile that you have set up

# Fix for pytest wont be able to import applications
export PYTHONPATH=src/

# Env variables
export STAGE="local-dev"
export SECRETS_NAME="${STAGE}/${SECRETS_NAME}"  # The name of secrets
export AWS_PROFILE=${AWS_PROFILE}

echo "Running Tests"
pipenv run python -m pytest tests/ -vv