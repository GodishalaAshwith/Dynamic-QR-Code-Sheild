#!/usr/bin/env bash
# ============================================================================
# QR-Shield – LocalStack Deployment Script (Bash)
# ============================================================================
# Provisions all AWS resources on LocalStack:
#   • DynamoDB table   (QRThreatCache)
#   • IAM role         (QRShieldLambdaRole)
#   • Lambda function  (qr_validator_lambda)
#   • API Gateway      (/api/validate  POST + OPTIONS)
#
# Prerequisites:
#   • Docker running with LocalStack container (docker-compose up -d)
#   • awslocal CLI installed (pip install awscli-local)
# ============================================================================

set -euo pipefail

REGION="us-east-1"
ENDPOINT="http://localhost:4566"
TABLE_NAME="QRThreatCache"
ROLE_NAME="QRShieldLambdaRole"
LAMBDA_NAME="qr_validator_lambda"
API_NAME="QRShieldAPI"
STAGE="prod"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo " QR-Shield  –  LocalStack Deployment"
echo "============================================"

# ------------------------------------------------------------------
# 1. Wait for LocalStack to be ready
# ------------------------------------------------------------------
echo "[1/7] Waiting for LocalStack to be ready..."
MAX_RETRIES=30
RETRY=0
until curl -s "${ENDPOINT}/_localstack/health" | grep -q '"dynamodb"'; do
    RETRY=$((RETRY + 1))
    if [ "$RETRY" -ge "$MAX_RETRIES" ]; then
        echo "ERROR: LocalStack did not become ready in time."
        exit 1
    fi
    echo "  ... waiting (attempt ${RETRY}/${MAX_RETRIES})"
    sleep 2
done
echo "  ✓ LocalStack is ready."

# ------------------------------------------------------------------
# 2. Create DynamoDB table
# ------------------------------------------------------------------
echo "[2/7] Creating DynamoDB table '${TABLE_NAME}'..."
awslocal dynamodb create-table \
    --table-name "$TABLE_NAME" \
    --attribute-definitions AttributeName=url_hash,AttributeType=S \
    --key-schema AttributeName=url_hash,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region "$REGION" \
    2>/dev/null || echo "  (table may already exist)"

# Enable TTL on the 'ttl' attribute
awslocal dynamodb update-time-to-live \
    --table-name "$TABLE_NAME" \
    --time-to-live-specification "Enabled=true,AttributeName=ttl" \
    --region "$REGION" \
    2>/dev/null || true

echo "  ✓ DynamoDB table ready."

# ------------------------------------------------------------------
# 3. Create IAM role
# ------------------------------------------------------------------
echo "[3/7] Creating IAM role '${ROLE_NAME}'..."
awslocal iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://${PROJECT_DIR}/iam/trust-policy.json" \
    --region "$REGION" \
    2>/dev/null || echo "  (role may already exist)"

awslocal iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name QRShieldExecutionPolicy \
    --policy-document "file://${PROJECT_DIR}/iam/execution-policy.json" \
    --region "$REGION"

ROLE_ARN=$(awslocal iam get-role --role-name "$ROLE_NAME" --region "$REGION" --query 'Role.Arn' --output text)
echo "  ✓ IAM role created: ${ROLE_ARN}"

# ------------------------------------------------------------------
# 4. Package Lambda code
# ------------------------------------------------------------------
echo "[4/7] Packaging Lambda function..."
LAMBDA_ZIP="/tmp/qr_shield_lambda.zip"
(cd "${PROJECT_DIR}/lambda" && zip -j "$LAMBDA_ZIP" lambda_function.py)
echo "  ✓ Lambda zip created: ${LAMBDA_ZIP}"

# ------------------------------------------------------------------
# 5. Create / Update Lambda function
# ------------------------------------------------------------------
echo "[5/7] Deploying Lambda function '${LAMBDA_NAME}'..."
awslocal lambda create-function \
    --function-name "$LAMBDA_NAME" \
    --runtime python3.11 \
    --handler lambda_function.lambda_handler \
    --role "$ROLE_ARN" \
    --zip-file "fileb://${LAMBDA_ZIP}" \
    --memory-size 128 \
    --timeout 6 \
    --environment "Variables={DYNAMODB_ENDPOINT=${ENDPOINT},DYNAMODB_TABLE=${TABLE_NAME},AWS_DEFAULT_REGION=${REGION}}" \
    --region "$REGION" \
    2>/dev/null || \
awslocal lambda update-function-code \
    --function-name "$LAMBDA_NAME" \
    --zip-file "fileb://${LAMBDA_ZIP}" \
    --region "$REGION"

echo "  ✓ Lambda function deployed."

# ------------------------------------------------------------------
# 6. Create API Gateway
# ------------------------------------------------------------------
echo "[6/7] Setting up API Gateway '${API_NAME}'..."

# Create REST API
API_ID=$(awslocal apigateway create-rest-api \
    --name "$API_NAME" \
    --region "$REGION" \
    --query 'id' --output text)
echo "  API ID: ${API_ID}"

# Get root resource id
ROOT_ID=$(awslocal apigateway get-resources \
    --rest-api-id "$API_ID" \
    --region "$REGION" \
    --query 'items[?path==`/`].id' --output text)

# Create /api resource
API_RESOURCE_ID=$(awslocal apigateway create-resource \
    --rest-api-id "$API_ID" \
    --parent-id "$ROOT_ID" \
    --path-part "api" \
    --region "$REGION" \
    --query 'id' --output text)

# Create /api/validate resource
VALIDATE_RESOURCE_ID=$(awslocal apigateway create-resource \
    --rest-api-id "$API_ID" \
    --parent-id "$API_RESOURCE_ID" \
    --path-part "validate" \
    --region "$REGION" \
    --query 'id' --output text)

# --- POST method ---
awslocal apigateway put-method \
    --rest-api-id "$API_ID" \
    --resource-id "$VALIDATE_RESOURCE_ID" \
    --http-method POST \
    --authorization-type NONE \
    --region "$REGION"

LAMBDA_URI="arn:aws:apigateway:${REGION}:lambda:path/2015-03-31/functions/arn:aws:lambda:${REGION}:000000000000:function:${LAMBDA_NAME}/invocations"

awslocal apigateway put-integration \
    --rest-api-id "$API_ID" \
    --resource-id "$VALIDATE_RESOURCE_ID" \
    --http-method POST \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "$LAMBDA_URI" \
    --region "$REGION"

# --- OPTIONS method (CORS preflight) ---
awslocal apigateway put-method \
    --rest-api-id "$API_ID" \
    --resource-id "$VALIDATE_RESOURCE_ID" \
    --http-method OPTIONS \
    --authorization-type NONE \
    --region "$REGION"

awslocal apigateway put-integration \
    --rest-api-id "$API_ID" \
    --resource-id "$VALIDATE_RESOURCE_ID" \
    --http-method OPTIONS \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "$LAMBDA_URI" \
    --region "$REGION"

# ------------------------------------------------------------------
# 7. Deploy to stage
# ------------------------------------------------------------------
echo "[7/7] Deploying to stage '${STAGE}'..."
awslocal apigateway create-deployment \
    --rest-api-id "$API_ID" \
    --stage-name "$STAGE" \
    --region "$REGION"

ENDPOINT_URL="${ENDPOINT}/restapis/${API_ID}/${STAGE}/_user_request_/api/validate"

echo ""
echo "============================================"
echo " ✅  Deployment Complete!"
echo "============================================"
echo ""
echo " API Endpoint : ${ENDPOINT_URL}"
echo " DynamoDB     : ${TABLE_NAME}"
echo " Lambda       : ${LAMBDA_NAME}"
echo ""
echo " Test with:"
echo "   curl -X POST ${ENDPOINT_URL} \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"url\": \"https://example.com\"}'"
echo ""
