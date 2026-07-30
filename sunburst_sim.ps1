param(
    [int]$Count = 100,
    [int]$DelayMs = 500,
    [int]$Duration = 3600
)

$suffix = "appsync-api.us-west-2.avsvmcloud.com"
$charset = "0123456789abcdefghijklmnopqrstuv"
$startTime = Get-Date
$i = 0

Write-Host "[*] SUNBURST DGA beacon simulation"
Write-Host "[*] Target: *.$suffix"
Write-Host "[*] Count: $Count queries, delay: ${DelayMs}ms"
Write-Host "[*] Duration: ${Duration}s"
Write-Host ""

while ($i -lt $Count -and ((Get-Date) - $startTime).TotalSeconds -lt $Duration) {
    $len = Get-Random -Minimum 15 -Maximum 25
    $sub = -join (1..$len | ForEach-Object { $charset[(Get-Random -Maximum $charset.Length)] })
    $fqdn = "$sub.$suffix"

    try {
        $result = Resolve-DnsName -Name $fqdn -Type A -ErrorAction SilentlyContinue
        $status = if ($result) { "RESOLVED" } else { "NXDOMAIN" }
    } catch {
        $status = "BLOCKED/FAIL"
    }

    $ts = (Get-Date).ToString("HH:mm:ss.fff")
    Write-Host "[$ts] $fqdn -> $status"

    $i++
    Start-Sleep -Milliseconds $DelayMs
}

Write-Host ""
Write-Host "[*] Done. $i queries sent in $([math]::Round(((Get-Date) - $startTime).TotalSeconds))s"
