param(
    [Parameter(Mandatory=$false)][string]$Token,
    [Parameter(Mandatory=$false)][string]$Cookie,
    [Parameter(Mandatory=$false)][int]$StartCursor = 1,
    [Parameter(Mandatory=$false)][int]$Limit = 50,
    [Parameter(Mandatory=$false)][string]$Direction = 'forward',
    [Parameter(Mandatory=$false)][int]$MaxRequests = 10000
)

# If not provided via params, you can hard-code here as defaults
if (-not $Token) { $Token = 'Bearer YOUR_JWT_HERE' }
if (-not $Cookie) { $Cookie = 'connect.sid=...; cf_clearance=...' }

$BaseUrl = 'https://common.xyz/api/internal/trpc/user.getXpsRanked'

# Ensure output folder
$outDir = Join-Path -Path (Get-Location) -ChildPath 'output'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function New-Headers {
    param([string]$Auth, [string]$Ck)
    return @{
        'authorization' = $Auth
        'cookie'        = $Ck
        'accept'        = '*/*'
        'accept-encoding' = 'gzip, deflate, br, zstd'
        'accept-language' = 'en-US,en;q=0.8'
        'content-type'    = 'application/json'
        'user-agent'      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'
        'origin'          = 'https://common.xyz'
        'referer'         = 'https://common.xyz/leaderboard'
    }
}

function Get-FirstArrayCount {
    param([Parameter(ValueFromPipeline=$true)]$Obj)
    if ($null -eq $Obj) { return 0 }
    if ($Obj -is [System.Collections.IEnumerable] -and -not ($Obj -is [string])) {
        # If it's an array, return its count
        try { return [int]$Obj.Count } catch { }
    }
    # Traverse properties recursively to find the first array with elements
    $props = $Obj | Get-Member -MemberType NoteProperty, Property, AliasProperty -ErrorAction SilentlyContinue
    foreach ($p in $props) {
        $val = $Obj.$($p.Name)
        if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
            try { return [int]$val.Count } catch { }
        }
        $inner = Get-FirstArrayCount -Obj $val
        if ($inner -gt 0) { return $inner }
    }
    return 0
}

$cursor = [int]$StartCursor
$requestIndex = 0
Write-Host ("Starting pagination from cursor={0}, limit={1}, direction={2}" -f $cursor, $Limit, $Direction)

while ($true) {
    if ($requestIndex -ge $MaxRequests) {
        Write-Warning "MaxRequests ($MaxRequests) reached. Stopping."
        break
    }
    $requestIndex++

    $inputObj = @{ limit = $Limit; cursor = $cursor; direction = $Direction }
    $inputJson = ($inputObj | ConvertTo-Json -Compress)
    $encoded = [System.Net.WebUtility]::UrlEncode($inputJson)
    $url = "$BaseUrl?input=$encoded"

    $headers = New-Headers -Auth $Token -Ck $Cookie

    try {
        $resp = Invoke-WebRequest -Uri $url -Headers $headers -Method GET -TimeoutSec 30 -ErrorAction Stop
        $status = $resp.StatusCode
        $body = $resp.Content
    } catch {
        Write-Warning ("Request failed at cursor {0}: {1}" -f $cursor, $_.Exception.Message)
        break
    }

    if ($status -lt 200 -or $status -ge 300) {
        Write-Warning ("Non-2xx status at cursor {0}: {1}" -f $cursor, $status)
        # Save error body for inspection
        $errPath = Join-Path $outDir ("page_{0}.error.txt" -f $cursor)
        $body | Out-File -FilePath $errPath -Encoding UTF8
        break
    }

    # Save page body
    $outPath = Join-Path $outDir ("page_{0}.json" -f $cursor)
    $body | Out-File -FilePath $outPath -Encoding UTF8

    # Decide whether to continue: parse JSON and find first array count
    $count = 0
    try {
        $json = $body | ConvertFrom-Json -ErrorAction Stop
        $count = Get-FirstArrayCount -Obj $json
    } catch {
        # If JSON parse fails, attempt a simple heuristic: look for empty array tokens
        if ($body -match '"\[\]"' -or $body -match '"items"\s*:\s*\[\s*\]') { $count = 0 } else { $count = 1 }
    }

    if ($count -le 0) {
        Write-Host ("No data at cursor={0}. Stopping." -f $cursor)
        break
    } else {
        Write-Host ("Cursor={0} -> items~{1}. Continuing..." -f $cursor, $count)
    }

    $cursor++
}

Write-Host "Done. Files saved under: $outDir"
