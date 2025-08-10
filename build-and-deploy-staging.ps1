# ---- edit these before running ----
$LambdaName = "my-staging-lambda"         # <- set staging lambda name
$UseDeploy = $true                        # <- set $false if you don't want to upload
# ------------------------------------

cd .


Write-Host "1) Installing production dependencies..."
npm install --omit=dev


Write-Host "2) Creating temporary build folder..."
$root = Get-Location
$buildDir = Join-Path $root "lambda_build"
if (Test-Path $buildDir) { Remove-Item $buildDir -Recurse -Force }
New-Item -ItemType Directory -Path $buildDir | Out-Null

Write-Host "3) Copying files to build folder (excluding .git, .env, tests, .github, lambda_build)..."
Get-ChildItem -Path $root -Force | Where-Object { $_.Name -notin @('.git', '.env', 'tests', '.github', 'lambda_build') } | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $buildDir -Recurse -Force
}


$zipPath = Join-Path $root "..\backend-function.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Write-Host "4) Zipping package to: $zipPath"
Compress-Archive -Path "$buildDir\*" -DestinationPath $zipPath -Force

Write-Host "5) Removing temporary build folder..."
Remove-Item $buildDir -Recurse -Force

Write-Host "6) AWS creds check (sts:GetCallerIdentity)..."
aws sts get-caller-identity
if ($LASTEXITCODE -ne 0) {
  Write-Error "AWS CLI credential check failed. Fix credentials before deploying."
  exit 1
}

if ($UseDeploy) {
  Write-Host "7) Uploading to Lambda: $LambdaName"
  aws lambda update-function-code --function-name $LambdaName --zip-file "fileb://$((Resolve-Path $zipPath).Path)"
  if ($LASTEXITCODE -ne 0) {
    Write-Error "Lambda update failed."
    exit 1
  }

  Write-Host "8) Invoking Lambda (test) and writing output to ./lambda-invoke-output.json ..."
  aws lambda invoke --function-name $LambdaName --payload '{}' ../lambda-invoke-output.json
  Write-Host "Invocation complete. See ../lambda-invoke-output.json"
}

Write-Host "Done. Remove the zip when finished if desired: Remove-Item $zipPath -Force"
