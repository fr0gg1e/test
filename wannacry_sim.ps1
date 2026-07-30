param(
    [int]$Count = 100,
    [int]$DelayMs = 500,
    [int]$Duration = 3600
)

$domain = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
$startTime = Get-Date
$i = 0

Write-Host "[*] WannaCry kill switch beacon simulation"
Write-Host "[*] Target: $domain"
Write-Host "[*] Count: $Count queries, delay: ${DelayMs}ms"
Write-Host "[*] Duration: ${Duration}s"
Write-Host ""

while ($i -lt $Count -and ((Get-Date) - $startTime).TotalSeconds -lt $Duration) {
    try {
        $result = Resolve-DnsName -Name $domain -Type A -ErrorAction SilentlyContinue
        if ($result) {
            $ips = ($result | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ","
            if ($ips) { $status = "RESOLVED [$ips]" } else { $status = "RESOLVED [no A record]" }
        } else {
            $status = "NXDOMAIN"
        }
    } catch {
        $status = "BLOCKED/FAIL"
    }

    $ts = (Get-Date).ToString("HH:mm:ss.fff")
    $line = "[$ts] $domain -> $status"
    Write-Host $line
    Add-Content -Path "wannacry_sim.log" -Value $line

    $i++
    Start-Sleep -Milliseconds $DelayMs
}

Write-Host ""
Write-Host "[*] Done. $i queries sent in $([math]::Round(((Get-Date) - $startTime).TotalSeconds))s"
