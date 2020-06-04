#!/usr/bin/env sh

PROFILE=compeat-dev # Your AWS profile that you have set up

export AWS_PROFILE=${PROFILE}

sh ./scripts/build.sh
clear
sam local start-api --env-vars templates/variables.json
