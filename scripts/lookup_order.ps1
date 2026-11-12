param(
    [string]$OrderId = "88848384PT830915A",
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Stop"

Write-Host "`n========== INTENTGUARD ORDER LOOKUP ==========" -ForegroundColor Cyan
Write-Host "Order ID: $OrderId"
Write-Host "Firewall: $BaseUrl"

# Load merchant key from environment or project .env.
$key = $env:INTENTGUARD_MERCHANT_API_KEY

if (-not $key) {
    $envFile = Join-Path (Get-Location) ".env"

    if (Test-Path $envFile) {
        $line = Get-Content $envFile |
            Where-Object { $_ -match '^\s*INTENTGUARD_MERCHANT_API_KEY\s*=' } |
            Select-Object -First 1

        if ($line) {
            $key = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'")
        }
    }
}

if (-not $key) {
    Write-Host "Merchant API key not found." -ForegroundColor Red
    Write-Host 'Set $env:INTENTGUARD_MERCHANT_API_KEY first.'
    exit 1
}

$headers = @{
    "X-Merchant-Key" = $key
}

# First inspect the actual API routes.
Write-Host "`n[1] Discovering API routes..." -ForegroundColor Yellow

try {
    $openapi = Invoke-RestMethod `
        -Uri "$BaseUrl/openapi.json" `
        -Method Get

    $openapi.paths.PSObject.Properties |
        Where-Object {
            $_.Name -match 'dashboard|orders|gate-status'
        } |
        ForEach-Object {
            Write-Host "`n$($_.Name)"
            Write-Host "Methods: $($_.Value.PSObject.Properties.Name -join ', ')"
        }
}
catch {
    Write-Host "OpenAPI discovery failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Query the known merchant gate-status route.
Write-Host "`n[2] Querying order gate status..." -ForegroundColor Yellow

$uri = "$BaseUrl/api/v1/mcp/orders/$([uri]::EscapeDataString($OrderId))/gate-status"

try {
    $result = Invoke-RestMethod `
        -Uri $uri `
        -Method Get `
        -Headers $headers

    Write-Host "`n========== BACKEND RESULT ==========" -ForegroundColor Green

    $result | ConvertTo-Json -Depth 20

    Write-Host "`nLookup completed. Verify the returned order ID and status."
}
catch {
    Write-Host "`n========== LOOKUP FAILED ==========" -ForegroundColor Red

    if ($_.Exception.Response) {
        Write-Host "HTTP: $([int]$_.Exception.Response.StatusCode)"
    }

    Write-Host $_.Exception.Message

    if ($_.ErrorDetails.Message) {
        Write-Host $_.ErrorDetails.Message
    }
}
finally {
    $key = $null
    $headers = $null
}