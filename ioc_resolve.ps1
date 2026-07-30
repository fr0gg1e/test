param(
    [string]$Server = "",
    [int]$DelayMs = 200
)

$domains = @(
    # === APT29 / Cozy Bear (SolarWinds SUNBURST) ===
    @{ Domain="avsvmcloud.com"; APT="APT29"; Campaign="SUNBURST SolarWinds" },
    @{ Domain="test.appsync-api.us-west-2.avsvmcloud.com"; APT="APT29"; Campaign="SUNBURST DGA subdomain" },

    # === APT28 / Fancy Bear (Sofacy) ===
    @{ Domain="malaytravelgroup.com"; APT="APT28"; Campaign="X-AGENT C2" },
    @{ Domain="worldhomeoutlet.com"; APT="APT29"; Campaign="Cobalt Strike C2 (CISA)" },
    @{ Domain="theyardservice.com"; APT="APT29"; Campaign="Cobalt Strike C2 (CISA)" },
    @{ Domain="drivres-update.info"; APT="APT28"; Campaign="Sofacy Dec 2015" },
    @{ Domain="intelnetservice.com"; APT="APT28"; Campaign="Sofacy Dec 2015" },
    @{ Domain="intelsupport.net"; APT="APT28"; Campaign="Sofacy Dec 2015" },
    @{ Domain="softupdates.info"; APT="APT28"; Campaign="Sofacy Dec 2015" },
    @{ Domain="cdnverify.net"; APT="APT28"; Campaign="Sofacy activity" },

    # === APT10 ===
    @{ Domain="acsocietyy.com"; APT="APT10"; Campaign="C2 IOC" },

    # === Project Sauron ===
    @{ Domain="rapidcomments.com"; APT="ProjectSauron"; Campaign="C2" },
    @{ Domain="bikessport.com"; APT="ProjectSauron"; Campaign="C2" },

    # === LummaC2 (2024-2025, CISA AA25-141B) ===
    @{ Domain="auctiondecadecontaii.shop"; APT="LummaC2"; Campaign="Infostealer C2" },
    @{ Domain="aytobusesre.com"; APT="LummaC2"; Campaign="Infostealer C2" },
    @{ Domain="lufyfeo.org"; APT="LummaC2"; Campaign="Infostealer C2" },

    # === Operation Snowman ===
    @{ Domain="suroot.com"; APT="Snowman"; Campaign="FireEye Op Snowman" },
    @{ Domain="effers.com"; APT="Snowman"; Campaign="FireEye Op Snowman" },

    # === Mofang APT ===
    @{ Domain="video.today-nytimes.com"; APT="Mofang"; Campaign="FoxIT report" },
    @{ Domain="api.officeonlinetool.com"; APT="Mofang"; Campaign="FoxIT report" },
    @{ Domain="ie.update-windows-microsoft.com"; APT="Mofang"; Campaign="FoxIT report" },

    # === WannaCry ===
    @{ Domain="iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"; APT="WannaCry"; Campaign="Kill switch" },

    # === Cobalt Strike C2 ===
    @{ Domain="api.skycloudcenter.com"; APT="CobaltStrike"; Campaign="C2 2025" },
    @{ Domain="api.cloudtrafficservice.com"; APT="CobaltStrike"; Campaign="C2 2025" },

    # === Test domains (vendor-specific) ===
    @{ Domain="malware.testcategory.com"; APT="TEST"; Campaign="Cloudflare Gateway" },
    @{ Domain="command-and-control.testcategory.com"; APT="TEST"; Campaign="Cloudflare Gateway" },
    @{ Domain="dns-malware-test.paloaltonetworks.com"; APT="TEST"; Campaign="Palo Alto DNS Security" },
    @{ Domain="testmyids.com"; APT="TEST"; Campaign="IDS test" }
)

$logFile = "ioc_resolve_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host "[*] IOC Domain Resolution Test"
Write-Host "[*] Domains: $($domains.Count)"
Write-Host "[*] Log: $logFile"
if ($Server) { Write-Host "[*] DNS Server: $Server" }
Write-Host ""
Write-Host ("{0,-50} {1,-15} {2,-25} {3}" -f "DOMAIN", "APT", "CAMPAIGN", "RESULT")
Write-Host ("-" * 120)

$header = "{0,-50} {1,-15} {2,-25} {3}" -f "DOMAIN", "APT", "CAMPAIGN", "RESULT"
Add-Content -Path $logFile -Value "IOC Domain Resolution Test - $(Get-Date)"
Add-Content -Path $logFile -Value $header
Add-Content -Path $logFile -Value ("-" * 120)

foreach ($entry in $domains) {
    $d = $entry.Domain
    $apt = $entry.APT
    $camp = $entry.Campaign

    try {
        if ($Server) {
            $result = Resolve-DnsName -Name $d -Type A -Server $Server -ErrorAction SilentlyContinue
        } else {
            $result = Resolve-DnsName -Name $d -Type A -ErrorAction SilentlyContinue
        }

        if ($result) {
            $ips = ($result | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ", "
            if ($ips) { $status = $ips } else { $status = "NO A RECORD" }
        } else {
            $status = "NXDOMAIN"
        }
    } catch {
        $status = "BLOCKED/FAIL"
    }

    $line = "{0,-50} {1,-15} {2,-25} {3}" -f $d, $apt, $camp, $status
    Write-Host $line
    Add-Content -Path $logFile -Value $line

    Start-Sleep -Milliseconds $DelayMs
}

Write-Host ""
Write-Host "[*] Done. Results saved to $logFile"
