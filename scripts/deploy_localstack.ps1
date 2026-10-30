<#
.SYNOPSIS
    QR-Shield - LocalStack Deployment Script (PowerShell for Windows)
.DESCRIPTION
    Provisions all required AWS resources on LocalStack:
      1. DynamoDB table: QRThreatCache (PK: url_hash, TTL enabled)
      2. IAM role: QRShieldLambdaRole with trust and least-privilege policies
      3. Lambda function: qr_validator_lambda (Python 3.11, 128MB, 6s timeout)
      4. Amazon API Gateway: REST API with POST and OPTIONS on /api/validate
      5. Deployment to 'prod' stage with full CORS support
#>

[CmdletBinding()]
param (
    [string]$EndpointUrl = "http://localhost:4566",
    [string]$Region = "us-east-1",
    [string]$TableName = "QRThreatCache",
    [string]$RoleName = "QRShieldLambdaRole",
    [string]$LambdaName = "qr_validator_lambda",
    [string]$ApiName = "QRShieldAPI",
    [string]$Stage = "prod"
)

$ErrorActionPreference = "Stop"

$ProjectDir = (Get-Item $PSScriptRoot).Parent.FullName
$LambdaDir  = Join-Path $ProjectDir "lambda"
$IamDir     = Join-Path $ProjectDir "iam"
$ZipPath    = Join-Path $env:TEMP "qr_shield_lambda.zip"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " QR-Shield - LocalStack Deployment (PowerShell)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ------------------------------------------------------------------
# 1. Health check LocalStack
# ------------------------------------------------------------------
Write-Host "[1/7] Checking LocalStack health at $EndpointUrl..." -ForegroundColor Yellow
$maxRetries = 20
$retry = 0
$healthy = $false

while (-not $healthy -and $retry -lt $maxRetries) {
    $retry++
    try {
        $healthResponse = Invoke-RestMethod -Uri "$EndpointUrl/_localstack/health" -Method Get -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($healthResponse.services.dynamodb -eq "available" -or $healthResponse.services.dynamodb -eq "running") {
            $healthy = $true
        } else {
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Host "  ... waiting for LocalStack (attempt $retry/$maxRetries)" -ForegroundColor Gray
        Start-Sleep -Seconds 2
    }
}

if (-not $healthy) {
    Write-Warning "Could not confirm LocalStack health via HTTP. Proceeding anyway with AWS CLI..."
} else {
    Write-Host "  [OK] LocalStack is online and responsive." -ForegroundColor Green
}

# ------------------------------------------------------------------
# 2. Create DynamoDB Table
# ------------------------------------------------------------------
Write-Host "[2/7] Creating DynamoDB table '$TableName'..." -ForegroundColor Yellow
try {
    aws --endpoint-url $EndpointUrl dynamodb create-table `
        --table-name $TableName `
        --attribute-definitions AttributeName=url_hash,AttributeType=S `
        --key-schema AttributeName=url_hash,KeyType=HASH `
        --billing-mode PAY_PER_REQUEST `
        --region $Region 2>$null | Out-Null
    Write-Host "  [OK] Table '$TableName' created." -ForegroundColor Green
} catch {
    Write-Host "  (Table may already exist, continuing...)" -ForegroundColor Gray
}

# Enable TTL on the 'ttl' attribute
aws --endpoint-url $EndpointUrl dynamodb update-time-to-live `
    --table-name $TableName `
    --time-to-live-specification "Enabled=true,AttributeName=ttl" `
    --region $Region 2>$null | Out-Null
Write-Host "  [OK] TTL enabled on attribute 'ttl'." -ForegroundColor Green

# ------------------------------------------------------------------
# 3. Create IAM Role and Attach Policy
# ------------------------------------------------------------------
Write-Host "[3/7] Creating IAM role '$RoleName'..." -ForegroundColor Yellow
$TrustPolicyPath = Join-Path $IamDir "trust-policy.json"
$ExecutionPolicyPath = Join-Path $IamDir "execution-policy.json"

try {
    aws --endpoint-url $EndpointUrl iam create-role `
        --role-name $RoleName `
        --assume-role-policy-document "file://$TrustPolicyPath" `
        --region $Region 2>$null | Out-Null
} catch {
    Write-Host "  (Role may already exist, updating policies...)" -ForegroundColor Gray
}

aws --endpoint-url $EndpointUrl iam put-role-policy `
    --role-name $RoleName `
    --policy-name "QRShieldExecutionPolicy" `
    --policy-document "file://$ExecutionPolicyPath" `
    --region $Region | Out-Null

$RoleArn = aws --endpoint-url $EndpointUrl iam get-role `
    --role-name $RoleName `
    --query "Role.Arn" `
    --output text `
    --region $Region

Write-Host "  [OK] IAM Role ARN: $RoleArn" -ForegroundColor Green

# ------------------------------------------------------------------
# 4. Package Lambda Code
# ------------------------------------------------------------------
Write-Host "[4/7] Packaging Lambda handler..." -ForegroundColor Yellow
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

$SourceFile = Join-Path $LambdaDir "lambda_function.py"
Compress-Archive -Path $SourceFile -DestinationPath $ZipPath -Force
Write-Host "  [OK] Zip archive created at $ZipPath" -ForegroundColor Green

# ------------------------------------------------------------------
# 5. Create / Update Lambda Function
# ------------------------------------------------------------------
Write-Host "[5/7] Deploying Lambda function '$LambdaName'..." -ForegroundColor Yellow
$EnvVars = "Variables={DYNAMODB_ENDPOINT=$EndpointUrl,DYNAMODB_TABLE=$TableName,AWS_DEFAULT_REGION=$Region}"

$lambdaExists = $false
try {
    aws --endpoint-url $EndpointUrl lambda get-function --function-name $LambdaName --region $Region 2>$null | Out-Null
    $lambdaExists = $true
} catch {
    $lambdaExists = $false
}

if ($lambdaExists) {
    aws --endpoint-url $EndpointUrl lambda update-function-code `
        --function-name $LambdaName `
        --zip-file "fileb://$ZipPath" `
        --region $Region | Out-Null
    Write-Host "  [OK] Lambda code updated." -ForegroundColor Green
} else {
    aws --endpoint-url $EndpointUrl lambda create-function `
        --function-name $LambdaName `
        --runtime python3.11 `
        --handler lambda_function.lambda_handler `
        --role $RoleArn `
        --zip-file "fileb://$ZipPath" `
        --memory-size 128 `
        --timeout 6 `
        --environment $EnvVars `
        --region $Region | Out-Null
    Write-Host "  [OK] Lambda function created." -ForegroundColor Green
}

# ------------------------------------------------------------------
# 6. Create API Gateway (REST API)
# ------------------------------------------------------------------
Write-Host "[6/7] Setting up Amazon API Gateway '$ApiName'..." -ForegroundColor Yellow

$ApiId = aws --endpoint-url $EndpointUrl apigateway create-rest-api `
    --name $ApiName `
    --region $Region `
    --query "id" `
    --output text

$RootId = aws --endpoint-url $EndpointUrl apigateway get-resources `
    --rest-api-id $ApiId `
    --region $Region `
    --query "items[?path=='/'].id" `
    --output text

$ApiResourceId = aws --endpoint-url $EndpointUrl apigateway create-resource `
    --rest-api-id $ApiId `
    --parent-id $RootId `
    --path-part "api" `
    --region $Region `
    --query "id" `
    --output text

$ValidateResourceId = aws --endpoint-url $EndpointUrl apigateway create-resource `
    --rest-api-id $ApiId `
    --parent-id $ApiResourceId `
    --path-part "validate" `
    --region $Region `
    --query "id" `
    --output text

# POST method & AWS_PROXY Integration
aws --endpoint-url $EndpointUrl apigateway put-method `
    --rest-api-id $ApiId `
    --resource-id $ValidateResourceId `
    --http-method POST `
    --authorization-type NONE `
    --region $Region | Out-Null

$LambdaUri = "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/arn:aws:lambda:${Region}:000000000000:function:${LambdaName}/invocations"

aws --endpoint-url $EndpointUrl apigateway put-integration `
    --rest-api-id $ApiId `
    --resource-id $ValidateResourceId `
    --http-method POST `
    --type AWS_PROXY `
    --integration-http-method POST `
    --uri $LambdaUri `
    --region $Region | Out-Null

# OPTIONS method for CORS preflight
aws --endpoint-url $EndpointUrl apigateway put-method `
    --rest-api-id $ApiId `
    --resource-id $ValidateResourceId `
    --http-method OPTIONS `
    --authorization-type NONE `
    --region $Region | Out-Null

aws --endpoint-url $EndpointUrl apigateway put-integration `
    --rest-api-id $ApiId `
    --resource-id $ValidateResourceId `
    --http-method OPTIONS `
    --type AWS_PROXY `
    --integration-http-method POST `
    --uri $LambdaUri `
    --region $Region | Out-Null

# ------------------------------------------------------------------
# 7. Deploy to Stage
# ------------------------------------------------------------------
Write-Host "[7/7] Deploying API to stage '$Stage'..." -ForegroundColor Yellow
aws --endpoint-url $EndpointUrl apigateway create-deployment `
    --rest-api-id $ApiId `
    --stage-name $Stage `
    --region $Region | Out-Null

$EndpointFinal = "$EndpointUrl/restapis/$ApiId/$Stage/_user_request_/api/validate"

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host " [SUCCESS] Deployment Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host " API Endpoint : $EndpointFinal" -ForegroundColor Cyan
Write-Host " DynamoDB     : $TableName" -ForegroundColor White
Write-Host " Lambda       : $LambdaName" -ForegroundColor White
Write-Host " Stage        : $Stage" -ForegroundColor White
Write-Host ""
Write-Host " Test using curl / Invoke-RestMethod:" -ForegroundColor Yellow
Write-Host "   curl -X POST `"$EndpointFinal`" -H `"Content-Type: application/json`" -d '{`"url`": `"https://www.cbit.ac.in`"}'" -ForegroundColor Gray
Write-Host ""

