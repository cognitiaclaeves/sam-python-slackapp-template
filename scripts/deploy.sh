#!/usr/bin/env sh
set -e

if [ -z "$1" ]
  then
    echo "Argument stage is required"
    exit 1
fi

# Aws Variables
STAGE=$1
# ACCOUNT_ID="<REPLACE_ME>"  # Your AWS account id
REGION="us-west-1"  # The AWS region you are building in e.g. ap-southeast-2
# AWS_PROFILE="<REPLACE_ME>"  # Your AWS profile that you have set up
BUCKET="compeat-${STAGE}-artifacts"  # An S3 bucket that can store lambda code in

# Stack Variables
SECRETS_NAME="${STAGE}/slack-helpdesk-creds"  # The name of the secret in secrets manager that stores
SERVICE="Slack-HelpDesk"  # The name of the service e.g. MySuperCoolSlackApp
STACK_NAME="${SERVICE}"  # The name of the stack. You could just use ${SERVICE} here

# File Pathing
TEMPLATE_FOLDER="templates"  # The folder which your template lives in
TEMPLATE_FILE="template.yml"  # the file that in your template folder it lives in
DIST_FOLDER="dist"  # A folder that the distribution files live in. Just leave this

# Export our set Aws Profile
export AWS_PROFILE=${AWS_PROFILE}

if [ "${SLACK_LAMBDA_MASTER_CUTOFF}" == '' ]; then
    bash ./scripts/test.sh
else
    echo "-- \$SLACK_LAMBDA_MASTER_CUTOFF engaged - Skipping tests for emergency deployment ..."
fi

echo "Removing Old Deployment Template"
rm -f ${DIST_FOLDER}/${STAGE}-packaged-template.yml

sh ./scripts/build.sh

# echo "CloudFormation packaging..."

mkdir -p ${DIST_FOLDER}


# sam deploy --stack-name advproxy-dev-pusher     --capabilities CAPABILITY_IAM     --parameter-overrides Environment=dev --region us-west-1

# pipenv requirements into src/build directory
# pipenv lock -r > ./src/build/requirements.txt

# sam build -t templates/template.yml

    # sam package --output-template-file packaged.dev.yaml     --s3-bucket compeat-dev-artifacts --s3-prefix compeat-devops-sam-lambda-deployments/advproxy-dev-pusher

    # # The prefix puts the UUID label under a human recognizable directory in S3

    # sam deploy --stack-name advproxy-dev-pusher     --capabilities CAPABILITY_IAM     --parameter-overrides Environment=dev --region us-west-1


sam package \
    --region ${REGION} \
    --template-file ${TEMPLATE_FOLDER}/${TEMPLATE_FILE} \
    --output-template-file ${DIST_FOLDER}/${STAGE}-packaged-template.yml \
    --s3-bucket ${BUCKET} \
    --s3-prefix compeat-devops-sam-lambda-deployments/${SERVICE}

# aws cloudformation package \
#     --region ${REGION} \
#     --template-file ${TEMPLATE_FOLDER}/${TEMPLATE_FILE} \
#     --output-template-file ${DIST_FOLDER}/${STAGE}-packaged-template.yml \
#     --s3-bucket ${BUCKET} \
#     --s3-prefix compeat-devops-sam-lambda-deployments/${SERVICE}

#     # --template-file ${DIST_FOLDER}/${STAGE}-packaged-template.yml \


sam deploy \
    --region ${REGION} \
    --stack-name ${STACK_NAME} \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
    --s3-bucket ${BUCKET} \
    --s3-prefix compeat-devops-sam-lambda-deployments/${SERVICE} \
    --parameter-overrides Stage=${STAGE} SecretsName=${SECRETS_NAME} ServiceName=${SERVICE}

# If stack in roll-back, use: 
# $ aws cloudformation delete-stack --stack-name Slack-HelpDesk


# echo "CloudFormation deploying..."
# aws cloudformation deploy  \
#     --region ${REGION} \
#     --template-file ${DIST_FOLDER}/${STAGE}-packaged-template.yml \
#     --stack-name ${STACK_NAME} \
#     --capabilities CAPABILITY_NAMED_IAM \
#     --parameter-override Stage=${STAGE} SecretsName=${SECRETS_NAME} ServiceName=${SERVICE}



# echo "CloudFormation outputs..."
# aws cloudformation describe-stacks \
#     --stack-name ${STACK_NAME} \
#     --query 'Stacks[].Outputs'