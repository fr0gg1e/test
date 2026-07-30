param(
    [string]$DoHServer = "https://cloudflare-dns.com/dns-query",
    [int]$DelayMs = 200
)

$domains = @(
    @{ Domain="avsvmcloud.com"; Group="APT29"; Family="SUNBURST"; Year=2020 },
    @{ Domain="008bqp230gps9dde71l4qld.appsync-api.us-east-1.avsvmcloud.com"; Group="APT29"; Family="SUNBURST"; Year=2020 },
    @{ Domain="dataplane.theyardservice.com"; Group="APT29"; Family="Cobalt Strike"; Year=2021 },
    @{ Domain="theyardservice.com"; Group="APT29"; Family="Cobalt Strike"; Year=2021 },
    @{ Domain="worldhomeoutlet.com"; Group="APT29"; Family="Cobalt Strike"; Year=2021 },
    @{ Domain="malaytravelgroup.com"; Group="APT28"; Family="X-AGENT"; Year=2018 },
    @{ Domain="rapidcomments.com"; Group="ProjectSauron"; Family="Remsec"; Year=2016 },
    @{ Domain="suroot.com"; Group="Snowman"; Family="ZxShell"; Year=2014 },
    @{ Domain="effers.com"; Group="Snowman"; Family="ZxShell"; Year=2014 },
    @{ Domain="iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"; Group="Lazarus"; Family="WannaCry"; Year=2017 },
    @{ Domain="westurn.in"; Group="TrickBot"; Family="TrickBot"; Year=2026 },
    @{ Domain="a1b2c3d4e5f6.westurn.in"; Group="TrickBot"; Family="TrickBot"; Year=2026 },
    @{ Domain="data.westurn.in"; Group="TrickBot"; Family="TrickBot"; Year=2026 },
    @{ Domain="aytobusesre.com"; Group="LummaC2"; Family="LummaC2"; Year=2024 },
    @{ Domain="popfealt.one"; Group="LummaC2"; Family="LummaC2"; Year=2024 },
    @{ Domain="api.cloudtrafficservice.com"; Group="CobaltStrike"; Family="Cobalt Strike"; Year=2026 },
    @{ Domain="securityhealthservice.ydns.eu"; Group="AsyncRAT"; Family="AsyncRAT"; Year=2024 },
    @{ Domain="systemcopilotdrivers.ydns.eu"; Group="AsyncRAT"; Family="AsyncRAT"; Year=2024 },
    @{ Domain="69cnc.duckdns.org"; Group="RAT"; Family="RAT"; Year=2026 },
    @{ Domain="lifeisabouthavingfun448.duckdns.org"; Group="RAT"; Family="RAT"; Year=2026 },
    @{ Domain="tamajailroster.org"; Group="ClearFake"; Family="ClearFake"; Year=2026 },
    @{ Domain="switchspineprint.com"; Group="ClearFake"; Family="ClearFake"; Year=2026 },
    @{ Domain="prairiefurnitureshop.com"; Group="ClearFake"; Family="ClearFake"; Year=2026 },
    @{ Domain="swirlscinnamonrolls.com"; Group="ClearFake"; Family="ClearFake"; Year=2026 },
    @{ Domain="stephanie-bates.com"; Group="ClearFake"; Family="ClearFake"; Year=2026 },
    @{ Domain="mulberrylodestar.top"; Group="SmartApeSG"; Family="SmartApeSG"; Year=2026 },
    @{ Domain="brewtrail.click"; Group="RevStealer"; Family="RevStealer"; Year=2026 },
    @{ Domain="push.brewtrail.click"; Group="RevStealer"; Family="RevStealer"; Year=2026 },
    @{ Domain="da.dojiner.at"; Group="Stealer"; Family="ArcaneStealer"; Year=2026 },
    @{ Domain="ph.dojiner.at"; Group="Stealer"; Family="ArcaneStealer"; Year=2026 },
    @{ Domain="smarwth.biz"; Group="Remus"; Family="RemusStealer"; Year=2026 },
    @{ Domain="chrome-windows.ru"; Group="FakeUpdate"; Family="ValleyRAT"; Year=2026 },
    @{ Domain="tashirpizza.su"; Group="Malware"; Family="Malware"; Year=2026 },
    @{ Domain="livepilates.com.sg"; Group="IClickFix"; Family="IClickFix"; Year=2026 },
    @{ Domain="liveproject.fr"; Group="IClickFix"; Family="IClickFix"; Year=2026 },
    @{ Domain="lifeisavicnic.com"; Group="IClickFix"; Family="IClickFix"; Year=2026 },
    @{ Domain="malware.testcategory.com"; Group="TEST"; Family="Test"; Year=2024 },
    @{ Domain="phishing.testcategory.com"; Group="TEST"; Family="Test"; Year=2024 },
    @{ Domain="command-and-control.testcategory.com"; Group="TEST"; Family="Test"; Year=2024 },
    @{ Domain="testmyids.com"; Group="TEST"; Family="Test"; Year=2024 },
    @{ Domain="wicar.org"; Group="TEST"; Family="Test"; Year=2024 }
)

function Resolve-DoH {
    param([string]$Name, [string]$Server)

    $url = "$Server`?name=$Name&type=A"
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers @{ "Accept" = "application/dns-json" } -ErrorAction Stop
        if ($resp.Answer) {
            $ips = ($resp.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data }) -join ", "
            if ($ips) { return $ips }
            $cnames = ($resp.Answer | Where-Object { $_.type -eq 5 } | ForEach-Object { $_.data }) -join ", "
            if ($cnames) { return "CNAME: $cnames" }
            return "NO A RECORD"
        }
        if ($resp.Status -eq 3) { return "NXDOMAIN" }
        return "EMPTY (status=$($resp.Status))"
    } catch {
        return "DOH-ERROR: $($_.Exception.Message)"
    }
}

$logFile = "ioc_doh_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$resolved = 0; $nxdomain = 0; $errors = 0

Write-Host "[*] IOC DoH Bypass Test"
Write-Host "[*] DoH Server: $DoHServer"
Write-Host "[*] Domains: $($domains.Count)"
Write-Host "[*] Transport: HTTPS/443 (bypasses UDP/53 DNS filtering)"
Write-Host ""
Write-Host ("{0,-65} {1,-14} {2,-14} {3}" -f "DOMAIN","GROUP","FAMILY","DoH RESULT")
Write-Host ("=" * 140)

Add-Content -Path $logFile -Value "IOC DoH Bypass Test - $(Get-Date)"
Add-Content -Path $logFile -Value "DoH Server: $DoHServer"
Add-Content -Path $logFile -Value ("=" * 140)

foreach ($d in $domains) {
    $result = Resolve-DoH -Name $d.Domain -Server $DoHServer

    if ($result -match "NXDOMAIN") { $nxdomain++ }
    elseif ($result -match "ERROR") { $errors++ }
    else { $resolved++ }

    $line = "{0,-65} {1,-14} {2,-14} {3}" -f $d.Domain, $d.Group, $d.Family, $result
    Write-Host $line
    Add-Content -Path $logFile -Value $line
    Start-Sleep -Milliseconds $DelayMs
}

Write-Host ""
Write-Host ("=" * 140)
Write-Host "[*] RESOLVED=$resolved | NXDOMAIN=$nxdomain | ERRORS=$errors | TOTAL=$($domains.Count)"
Write-Host "[*] Log: $logFile"
Write-Host ""
Write-Host "[*] Porownaj z: .\ioc_master.ps1 (UDP/53)"
Write-Host "    Jesli master blokuje a doh przepuszcza = filtr DNS obejscie potwierdzone"

Add-Content -Path $logFile -Value ""
Add-Content -Path $logFile -Value "RESOLVED=$resolved NXDOMAIN=$nxdomain ERRORS=$errors TOTAL=$($domains.Count)"
