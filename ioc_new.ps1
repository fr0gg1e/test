param(
    [string]$Server = "",
    [int]$DelayMs = 300
)

$queries = @(
    # === TrickBot DNS tunneling ===
    @{ Domain="westurn.in"; APT="TrickBot"; Note="DNS tunnel C2 root" },
    @{ Domain="a1b2c3d4e5f6.westurn.in"; APT="TrickBot"; Note="DNS tunnel C2 sub" },
    @{ Domain="data.westurn.in"; APT="TrickBot"; Note="DNS tunnel C2 sub" },

    # === AsyncRAT / Remcos DDNS abuse ===
    @{ Domain="securityhealthservice.ydns.eu"; APT="AsyncRAT"; Note="DDNS C2 (ydns.eu)" },
    @{ Domain="systemcopilotdrivers.ydns.eu"; APT="AsyncRAT"; Note="DDNS C2 (ydns.eu)" },
    @{ Domain="69cnc.duckdns.org"; APT="RAT"; Note="CNC via DuckDNS" },
    @{ Domain="lifeisabouthavingfun448.duckdns.org"; APT="RAT"; Note="RAT C2 DuckDNS" },

    # === LummaC2 (Unit42 + ThreatFox) ===
    @{ Domain="auctiondecadecontaii.shop"; APT="LummaC2"; Note="Infostealer C2" },
    @{ Domain="aytobusesre.com"; APT="LummaC2"; Note="Infostealer C2" },
    @{ Domain="lufyfeo.org"; APT="LummaC2"; Note="Infostealer C2" },
    @{ Domain="popfealt.one"; APT="LummaC2"; Note="Infostealer C2 (Unit42)" },
    @{ Domain="horaot.org"; APT="LummaC2"; Note="Infostealer C2 (Unit42)" },

    # === Fake update / URLhaus active ===
    @{ Domain="chrome-windows.ru"; APT="FakeUpd"; Note="Fake Chrome download" },
    @{ Domain="tashirpizza.su"; APT="Malware"; Note="URLhaus active malware" },

    # === ThreatFox C2 ===
    @{ Domain="smarwth.biz"; APT="Remus"; Note="ThreatFox C2" },

    # === Cobalt Strike active ===
    @{ Domain="api.cloudtrafficservice.com"; APT="CS"; Note="Active Cobalt Strike C2" },

    # === Zeus GameOver DGA ===
    @{ Domain="jbcyxsgqovvucifaqbadagqeadx.net"; APT="Zeus"; Note="GameOver DGA" },
    @{ Domain="alnzkrgiswthigasorkovkqw.info"; APT="Zeus"; Note="GameOver DGA" },
    @{ Domain="cqzllwsprhdercfqwsql.com"; APT="Zeus"; Note="GameOver DGA" },

    # === Conficker DGA ===
    @{ Domain="aaidpkf.info"; APT="Conficker"; Note="DGA domain" },
    @{ Domain="bsjflk.com"; APT="Conficker"; Note="DGA domain" }
)

$logFile = "ioc_new_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$sinkhole = "62.0.58.94"
$blocked = 0
$resolved = 0
$nxdomain = 0

Write-Host "[*] IOC New Domains Resolution Test"
Write-Host "[*] Queries: $($queries.Count)"
Write-Host "[*] Log: $logFile"
if ($Server) { Write-Host "[*] DNS Server: $Server" }
Write-Host ""
Write-Host ("{0,-55} {1,-12} {2,-28} {3}" -f "DOMAIN", "APT", "NOTE", "RESULT")
Write-Host ("=" * 130)

$header = "{0,-55} {1,-12} {2,-28} {3}" -f "DOMAIN", "APT", "NOTE", "RESULT"
Add-Content -Path $logFile -Value "IOC New Domains Resolution Test - $(Get-Date)"
Add-Content -Path $logFile -Value $header
Add-Content -Path $logFile -Value ("=" * 130)

foreach ($q in $queries) {
    try {
        if ($Server) {
            $result = Resolve-DnsName -Name $q.Domain -Type A -Server $Server -ErrorAction SilentlyContinue
        } else {
            $result = Resolve-DnsName -Name $q.Domain -Type A -ErrorAction SilentlyContinue
        }

        if ($result) {
            $ips = ($result | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ", "
            if (-not $ips) { $ips = "NO A RECORD" }

            if ($ips -match $sinkhole) {
                $status = "BLOCKED (DNS Trap: $ips)"
                $blocked++
            } else {
                $status = $ips
                $resolved++
            }
        } else {
            $status = "NXDOMAIN"
            $nxdomain++
        }
    } catch {
        $status = "BLOCKED/FAIL"
        $blocked++
    }

    $line = "{0,-55} {1,-12} {2,-28} {3}" -f $q.Domain, $q.APT, $q.Note, $status
    Write-Host $line
    Add-Content -Path $logFile -Value $line

    Start-Sleep -Milliseconds $DelayMs
}

Write-Host ""
Write-Host ("=" * 130)
Write-Host "[*] Summary: BLOCKED=$blocked | RESOLVED=$resolved | NXDOMAIN=$nxdomain | TOTAL=$($queries.Count)"
Write-Host "[*] Results saved to $logFile"

Add-Content -Path $logFile -Value ""
Add-Content -Path $logFile -Value "Summary: BLOCKED=$blocked | RESOLVED=$resolved | NXDOMAIN=$nxdomain | TOTAL=$($queries.Count)"
