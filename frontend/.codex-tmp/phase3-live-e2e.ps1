$ErrorActionPreference = 'Stop'
$repo = 'C:\Users\adith\OneDrive\Desktop\FailProof'
$backend = Join-Path $repo 'backend'
$temp = Join-Path $repo 'frontend\.codex-tmp'
$python = 'C:\Users\adith\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$env:TEMP = $temp; $env:TMP = $temp
$env:DATABASE_URL = 'sqlite:///' + ((Join-Path $temp 'phase3-live.sqlite3').Replace('\','/'))
$env:FAILPROOF_DEMO_DB = Join-Path $temp 'phase3-live-demo.sqlite3'
$env:FAILPROOF_DEMO_ENABLED = '1'
$env:FAILPROOF_SCAN_ALLOWED_ROOTS = Join-Path $backend 'tests\fixtures'
$env:FAILPROOF_SCAN_TEMP_DIR = $temp
$apiLog = Join-Path $temp 'phase3-live-api.log'; $demoLog = Join-Path $temp 'phase3-live-demo.log'
$api = Start-Process -FilePath $python -ArgumentList @('-m','uvicorn','app.main:app','--host','127.0.0.1','--port','18000') -WorkingDirectory $backend -WindowStyle Hidden -RedirectStandardOutput $apiLog -RedirectStandardError ($apiLog + '.err') -PassThru
$demo = Start-Process -FilePath $python -ArgumentList @('-m','uvicorn','demo_api.app:app','--host','127.0.0.1','--port','8765') -WorkingDirectory $repo -WindowStyle Hidden -RedirectStandardOutput $demoLog -RedirectStandardError ($demoLog + '.err') -PassThru
try {
  $ready = $false
  for ($i=0; $i -lt 40; $i++) { try { Invoke-RestMethod 'http://127.0.0.1:18000/api/health' -TimeoutSec 2 | Out-Null; $ready=$true; break } catch { Start-Sleep -Milliseconds 500 } }
  if (-not $ready) { throw 'Backend did not become ready; inspect retained phase3-live-api.log files.' }
  $project = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:18000/api/projects' -ContentType 'application/json' -Body (@{name='Phase 3 live verification';description='Synthetic local verification'} | ConvertTo-Json)
  $projectId = $project.id
  $sourcePath = Join-Path $backend 'tests\fixtures\security'
  $source = Invoke-RestMethod -Method Put -Uri "http://127.0.0.1:18000/api/projects/$projectId/security/source" -ContentType 'application/json' -Body (@{source_path=$sourcePath;authorized=$true} | ConvertTo-Json)
  $static = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:18000/api/projects/$projectId/security/scans" -ContentType 'application/json' -Body (@{scan_type='static'} | ConvertTo-Json)
  $target = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:18000/api/projects/$projectId/targets" -ContentType 'application/json' -Body (@{name='Local synthetic demo';base_url='http://127.0.0.1:8765';authorized=$true;approve_non_safe_methods=$true} | ConvertTo-Json)
  $spec = Get-Content (Join-Path $repo 'demo_api\openapi.yaml') -Raw
  Invoke-WebRequest -Method Post -Uri "http://127.0.0.1:18000/api/targets/$($target.id)/specifications?filename=openapi.yaml" -ContentType 'application/yaml' -Body $spec | Out-Null
  $apiScan = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:18000/api/projects/$projectId/security/scans" -ContentType 'application/json' -Body (@{scan_type='api_security';approve_state_changes=$false} | ConvertTo-Json)
  $logic = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:18000/api/projects/$projectId/security/scans" -ContentType 'application/json' -Body (@{scan_type='business_logic';approve_state_changes=$true} | ConvertTo-Json)
  foreach ($scanVar in @('static','apiScan','logic')) { for ($attempt=0; $attempt -lt 60; $attempt++) { $scanObject = Get-Variable -Name $scanVar -ValueOnly; $scanObject = Invoke-RestMethod "http://127.0.0.1:18000/api/security/scans/$($scanObject.id)"; Set-Variable -Name $scanVar -Value $scanObject; if ($scanObject.status -notin @('queued','running')) { break }; Start-Sleep -Milliseconds 500 } }  $findings = Invoke-RestMethod "http://127.0.0.1:18000/api/projects/$projectId/security/findings"
  [pscustomobject]@{project_id=$projectId;source_registered=$source.configured;static_status=$static.status;static_findings=$static.finding_count;api_security_status=$apiScan.status;api_security_findings=$apiScan.finding_count;business_logic_status=$logic.status;business_logic_findings=$logic.finding_count;finding_statuses=@($findings | ForEach-Object { $_.status });evidence_records=@(($findings | ForEach-Object { $_.evidence.Count }) | Measure-Object -Sum).Sum} | ConvertTo-Json -Compress
} finally {
  Stop-Process -Id $api.Id -Force -ErrorAction SilentlyContinue
  Stop-Process -Id $demo.Id -Force -ErrorAction SilentlyContinue
}


