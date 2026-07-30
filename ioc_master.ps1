param(
    [string]$Server = "",
    [int]$DelayMs = 200
)

$domains = @(
    # === APT29 / Cozy Bear (Russia, SVR) ===
    @{ Domain="avsvmcloud.com"; Group="APT29"; Family="SUNBURST"; Year=2020; Type="C2 Root";
       Source="CISA AA20-352A"; Desc="SolarWinds supply chain - 18k orgs compromised" },
    @{ Domain="008bqp230gps9dde71l4qld.appsync-api.us-east-1.avsvmcloud.com"; Group="APT29"; Family="SUNBURST"; Year=2020; Type="C2 DGA";
       Source="FireEye/Mandiant"; Desc="DGA beacon - victim hostname encoded base32" },
    @{ Domain="02m6hcopd17p6h450gt3.appsync-api.us-west-2.avsvmcloud.com"; Group="APT29"; Family="SUNBURST"; Year=2020; Type="C2 DGA";
       Source="FireEye/Mandiant"; Desc="DGA beacon subdomain" },
    @{ Domain="039n5tnndkhrfn5cun0y0sz02hij0b12.appsync-api.us-west-2.avsvmcloud.com"; Group="APT29"; Family="SUNBURST"; Year=2020; Type="C2 DGA";
       Source="FireEye/Mandiant"; Desc="DGA beacon subdomain" },
    @{ Domain="043o9vacvthf0v95t81l.appsync-api.us-east-2.avsvmcloud.com"; Group="APT29"; Family="SUNBURST"; Year=2020; Type="C2 DGA";
       Source="FireEye/Mandiant"; Desc="DGA beacon subdomain" },
    @{ Domain="030cudhvc4crsl5cn660en66hoi3ts2f.appsync-api.us-west-2.avsvmcloud.com"; Group="APT29"; Family="SUNBURST"; Year=2020; Type="C2 DGA";
       Source="FireEye/Mandiant"; Desc="DGA beacon subdomain" },
    @{ Domain="dataplane.theyardservice.com"; Group="APT29"; Family="Cobalt Strike"; Year=2021; Type="C2";
       Source="CISA AA21-148A"; Desc="CS beacon - URI /jquery-3.3.1.min.woff2" },
    @{ Domain="cdn.theyardservice.com"; Group="APT29"; Family="Cobalt Strike"; Year=2021; Type="C2";
       Source="CISA AA21-148A"; Desc="CS beacon subdomain" },
    @{ Domain="static.theyardservice.com"; Group="APT29"; Family="Cobalt Strike"; Year=2021; Type="C2";
       Source="CISA AA21-148A"; Desc="CS beacon subdomain" },
    @{ Domain="theyardservice.com"; Group="APT29"; Family="Cobalt Strike"; Year=2021; Type="C2 Root";
       Source="CISA AA21-148A"; Desc="Spearphishing ISO distribution" },
    @{ Domain="worldhomeoutlet.com"; Group="APT29"; Family="Cobalt Strike"; Year=2021; Type="C2";
       Source="CISA AA21-148A"; Desc="CS C2 - Canadian hosting 192.99.221.77" },

    # === APT28 / Fancy Bear (Russia, GRU) ===
    @{ Domain="malaytravelgroup.com"; Group="APT28"; Family="X-AGENT"; Year=2018; Type="C2";
       Source="UK NCSC Oct 2018"; Desc="X-AGENT RAT - RSA-1024 encrypted comms, sinkholed CNAME" },

    # === Project Sauron / Strider ===
    @{ Domain="rapidcomments.com"; Group="ProjectSauron"; Family="Remsec"; Year=2016; Type="C2";
       Source="Kaspersky GReAT Aug 2016"; Desc="Modular cyberespionage - govt/military/finance" },

    # === Operation Snowman (China-linked) ===
    @{ Domain="suroot.com"; Group="Snowman"; Family="ZxShell"; Year=2014; Type="C2";
       Source="FireEye Feb 2014"; Desc="IE zero-day watering hole on US military" },
    @{ Domain="effers.com"; Group="Snowman"; Family="ZxShell"; Year=2014; Type="C2";
       Source="FireEye Feb 2014"; Desc="ZxShell RAT C2" },

    # === WannaCry / Lazarus (North Korea) ===
    @{ Domain="iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"; Group="Lazarus"; Family="WannaCry"; Year=2017; Type="Kill Switch";
       Source="MalwareTech/Cloudflare"; Desc="Kill switch - NOT C2 - stops ransomware propagation" },

    # === TrickBot (eCrime) ===
    @{ Domain="westurn.in"; Group="TrickBot"; Family="TrickBot"; Year=2026; Type="C2 DNS Tunnel";
       Source="Fortinet FortiGuard Labs"; Desc="DNS tunneling - XOR 0xB9, hex subdomains via 8.8.8.8" },
    @{ Domain="a1b2c3d4e5f6.westurn.in"; Group="TrickBot"; Family="TrickBot"; Year=2026; Type="C2 Sub";
       Source="Fortinet FortiGuard Labs"; Desc="DNS tunnel encoded subdomain" },
    @{ Domain="data.westurn.in"; Group="TrickBot"; Family="TrickBot"; Year=2026; Type="C2 Sub";
       Source="Fortinet FortiGuard Labs"; Desc="DNS tunnel data subdomain" },

    # === LummaC2 (eCrime MaaS) ===
    @{ Domain="aytobusesre.com"; Group="LummaC2"; Family="LummaC2"; Year=2024; Type="C2";
       Source="Unit42 Mar 2024"; Desc="Infostealer C2" },
    @{ Domain="popfealt.one"; Group="LummaC2"; Family="LummaC2"; Year=2024; Type="C2";
       Source="Unit42 Mar 2024"; Desc="Infostealer C2" },

    # === Cobalt Strike (eCrime / APT tool) ===
    @{ Domain="api.cloudtrafficservice.com"; Group="CobaltStrike"; Family="Cobalt Strike"; Year=2026; Type="C2";
       Source="Validin/hunt.io"; Desc="Active team server - Notepad++ supply chain link" },

    # === AsyncRAT / Remcos (DDNS abuse) ===
    @{ Domain="securityhealthservice.ydns.eu"; Group="AsyncRAT"; Family="AsyncRAT"; Year=2024; Type="C2 DDNS";
       Source="Derp.ca research"; Desc="DDNS C2 - shared pipeline with Remcos/DCRat" },
    @{ Domain="systemcopilotdrivers.ydns.eu"; Group="AsyncRAT"; Family="AsyncRAT"; Year=2024; Type="C2 DDNS";
       Source="Derp.ca research"; Desc="DDNS C2 - archive.org stego campaign" },
    @{ Domain="69cnc.duckdns.org"; Group="RAT"; Family="RAT"; Year=2026; Type="C2 DDNS";
       Source="URLhaus (abuse.ch)"; Desc="DuckDNS C2 abuse" },
    @{ Domain="lifeisabouthavingfun448.duckdns.org"; Group="RAT"; Family="RAT"; Year=2026; Type="C2 DDNS";
       Source="URLhaus (abuse.ch)"; Desc="DuckDNS C2 abuse" },

    # === ClearFake (fake browser update) ===
    @{ Domain="tamajailroster.org"; Group="ClearFake"; Family="ClearFake"; Year=2026; Type="Loader";
       Source="ThreatFox Jul 2026"; Desc="Compromised site - fake browser update JS" },
    @{ Domain="switchspineprint.com"; Group="ClearFake"; Family="ClearFake"; Year=2026; Type="Loader";
       Source="ThreatFox Jul 2026"; Desc="ClearFake payload distribution" },
    @{ Domain="prairiefurnitureshop.com"; Group="ClearFake"; Family="ClearFake"; Year=2026; Type="Loader";
       Source="ThreatFox Jul 2026"; Desc="ClearFake payload distribution" },
    @{ Domain="swirlscinnamonrolls.com"; Group="ClearFake"; Family="ClearFake"; Year=2026; Type="Loader";
       Source="ThreatFox Jul 2026"; Desc="ClearFake payload distribution" },
    @{ Domain="stephanie-bates.com"; Group="ClearFake"; Family="ClearFake"; Year=2026; Type="Loader";
       Source="ThreatFox Jul 2026"; Desc="ClearFake payload distribution" },
    # === SmartApeSG (botnet) ===
    @{ Domain="mulberrylodestar.top"; Group="SmartApeSG"; Family="SmartApeSG"; Year=2026; Type="C2";
       Source="ThreatFox Jul 2026"; Desc="Botnet C2 - delivers NetSupport RAT" },

    # === RevStealer ===
    @{ Domain="brewtrail.click"; Group="RevStealer"; Family="RevStealer"; Year=2026; Type="C2";
       Source="ThreatFox Jul 2026"; Desc="Credential stealer C2" },
    @{ Domain="push.brewtrail.click"; Group="RevStealer"; Family="RevStealer"; Year=2026; Type="C2 Sub";
       Source="ThreatFox Jul 2026"; Desc="RevStealer push notification sub" },

    # === ArcaneStealer ===
    @{ Domain="da.dojiner.at"; Group="Stealer"; Family="ArcaneStealer"; Year=2026; Type="C2";
       Source="ThreatFox IOC #1762235"; Desc="Stealer C2 infrastructure" },
    @{ Domain="ph.dojiner.at"; Group="Stealer"; Family="ArcaneStealer"; Year=2026; Type="C2";
       Source="ThreatFox Jul 2026"; Desc="Stealer C2 infrastructure" },

    # === Remus Stealer ===
    @{ Domain="smarwth.biz"; Group="Remus"; Family="RemusStealer"; Year=2026; Type="C2";
       Source="ThreatFox Jul 2026"; Desc="LummaC2 fork - credential stealer" },

    # === Fake Downloads / URLhaus ===
    @{ Domain="chrome-windows.ru"; Group="FakeUpdate"; Family="ValleyRAT"; Year=2026; Type="Distribution";
       Source="URLhaus (abuse.ch)"; Desc="Fake Chrome download serving malware" },
    @{ Domain="tashirpizza.su"; Group="Malware"; Family="Malware"; Year=2026; Type="Distribution";
       Source="URLhaus Jul 2026"; Desc="Active malware distribution .su TLD" },

    # === IClickFix ===
    @{ Domain="livepilates.com.sg"; Group="IClickFix"; Family="IClickFix"; Year=2026; Type="Distribution";
       Source="ThreatFox Jul 2026"; Desc="Fake CAPTCHA - delivers NetSupport RAT via PS" },
    @{ Domain="liveproject.fr"; Group="IClickFix"; Family="IClickFix"; Year=2026; Type="Distribution";
       Source="ThreatFox Jul 2026"; Desc="Compromised site - IClickFix campaign" },
    @{ Domain="lifeisavicnic.com"; Group="IClickFix"; Family="IClickFix"; Year=2026; Type="Distribution";
       Source="ThreatFox Jul 2026"; Desc="Compromised site - IClickFix campaign" },

    # === Vendor Test Domains ===
    @{ Domain="malware.testcategory.com"; Group="TEST"; Family="Test"; Year=2024; Type="Test";
       Source="Cloudflare Gateway"; Desc="Malware category filter test" },
    @{ Domain="phishing.testcategory.com"; Group="TEST"; Family="Test"; Year=2024; Type="Test";
       Source="Cloudflare Gateway"; Desc="Phishing category filter test" },
    @{ Domain="command-and-control.testcategory.com"; Group="TEST"; Family="Test"; Year=2024; Type="Test";
       Source="Cloudflare Gateway"; Desc="C2 category filter test" },
    @{ Domain="testmyids.com"; Group="TEST"; Family="Test"; Year=2024; Type="Test";
       Source="Community"; Desc="IDS/IPS testing domain" },
    @{ Domain="wicar.org"; Group="TEST"; Family="Test"; Year=2024; Type="Test";
       Source="EICAR equivalent"; Desc="Anti-malware web testing" }
)

$logFile = "ioc_master_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$cpTrap = "62.0.58.94"
$resolved = 0; $nxdomain = 0; $blocked = 0

Write-Host "[*] IOC Master - $($domains.Count) domains"
if ($Server) { Write-Host "[*] DNS: $Server" }
Write-Host ""
Write-Host ("{0,-65} {1,-14} {2,-14} {3,-6} {4}" -f "DOMAIN","GROUP","FAMILY","YEAR","RESULT")
Write-Host ("=" * 140)

Add-Content -Path $logFile -Value "IOC Master - $(Get-Date) - DNS: $(if ($Server) {$Server} else {'default'})"
Add-Content -Path $logFile -Value ("=" * 140)

foreach ($d in $domains) {
    try {
        if ($Server) {
            $r = Resolve-DnsName -Name $d.Domain -Type A -Server $Server -ErrorAction Stop
        } else {
            $r = Resolve-DnsName -Name $d.Domain -Type A -ErrorAction Stop
        }

        $ips = ($r | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ", "
        if (-not $ips) { $ips = "CNAME/NO-A" }

        if ($ips -match [regex]::Escape($cpTrap)) {
            $status = "BLOCKED (CP Trap: $ips)"
            $blocked++
        } else {
            $status = $ips
            $resolved++
        }
    } catch {
        if ($_.Exception.Message -match "does not exist|non-existent") {
            $status = "NXDOMAIN"
            $nxdomain++
        } else {
            $status = "ERROR"
            $nxdomain++
        }
    }

    $line = "{0,-65} {1,-14} {2,-14} {3,-6} {4}" -f $d.Domain, $d.Group, $d.Family, $d.Year, $status
    Write-Host $line
    Add-Content -Path $logFile -Value $line
    Start-Sleep -Milliseconds $DelayMs
}

Write-Host ""
Write-Host ("=" * 140)
Write-Host "[*] RESOLVED=$resolved | NXDOMAIN=$nxdomain | BLOCKED=$blocked | TOTAL=$($domains.Count)"

if ($nxdomain -gt 0) {
    Write-Host "[!] $nxdomain domen nie resolvuje - wywal przed testem na filtrze" -ForegroundColor Yellow
} else {
    Write-Host "[OK] Wszystko resolvuje - git" -ForegroundColor Green
}

Write-Host "[*] Log: $logFile"
Add-Content -Path $logFile -Value "RESOLVED=$resolved NXDOMAIN=$nxdomain BLOCKED=$blocked TOTAL=$($domains.Count)"
