#!/usr/bin/env bash

SECRETS_NAME="slack-helpdesk-creds"  # The name of the secret in secrets manager that stores
AWS_PROFILE="compeat-dev"  # Your AWS profile that you have set up

# Fix for pytest wont be able to import applications
export PYTHONPATH=src/

# Env variables
export STAGE="local-dev"
export SECRETS_NAME="${STAGE}/${SECRETS_NAME}"  # The name of secrets
export AWS_PROFILE=${AWS_PROFILE}

echo "Running Tests" "$@"
# pass -v for verbose, -vv for more verbose, -k to match test name, etc
pipenv run python -m pytest tests/ "$@"