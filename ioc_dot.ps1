param(
    [string]$DoTServer = "",
    [int]$DoTPort = 853,
    [int]$DelayMs = 200
)

if (-not $DoTServer) {
    Write-Host "Usage: .\ioc_dot.ps1 -DoTServer <VPS_IP>"
    exit
}

$domains = @(
    @{ Domain="avsvmcloud.com"; Group="APT29"; Family="SUNBURST" },
    @{ Domain="008bqp230gps9dde71l4qld.appsync-api.us-east-1.avsvmcloud.com"; Group="APT29"; Family="SUNBURST" },
    @{ Domain="dataplane.theyardservice.com"; Group="APT29"; Family="Cobalt Strike" },
    @{ Domain="theyardservice.com"; Group="APT29"; Family="Cobalt Strike" },
    @{ Domain="worldhomeoutlet.com"; Group="APT29"; Family="Cobalt Strike" },
    @{ Domain="malaytravelgroup.com"; Group="APT28"; Family="X-AGENT" },
    @{ Domain="rapidcomments.com"; Group="ProjectSauron"; Family="Remsec" },
    @{ Domain="suroot.com"; Group="Snowman"; Family="ZxShell" },
    @{ Domain="effers.com"; Group="Snowman"; Family="ZxShell" },
    @{ Domain="iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"; Group="Lazarus"; Family="WannaCry" },
    @{ Domain="westurn.in"; Group="TrickBot"; Family="TrickBot" },
    @{ Domain="a1b2c3d4e5f6.westurn.in"; Group="TrickBot"; Family="TrickBot" },
    @{ Domain="data.westurn.in"; Group="TrickBot"; Family="TrickBot" },
    @{ Domain="aytobusesre.com"; Group="LummaC2"; Family="LummaC2" },
    @{ Domain="popfealt.one"; Group="LummaC2"; Family="LummaC2" },
    @{ Domain="api.cloudtrafficservice.com"; Group="CobaltStrike"; Family="Cobalt Strike" },
    @{ Domain="securityhealthservice.ydns.eu"; Group="AsyncRAT"; Family="AsyncRAT" },
    @{ Domain="systemcopilotdrivers.ydns.eu"; Group="AsyncRAT"; Family="AsyncRAT" },
    @{ Domain="69cnc.duckdns.org"; Group="RAT"; Family="RAT" },
    @{ Domain="lifeisabouthavingfun448.duckdns.org"; Group="RAT"; Family="RAT" },
    @{ Domain="tamajailroster.org"; Group="ClearFake"; Family="ClearFake" },
    @{ Domain="switchspineprint.com"; Group="ClearFake"; Family="ClearFake" },
    @{ Domain="prairiefurnitureshop.com"; Group="ClearFake"; Family="ClearFake" },
    @{ Domain="swirlscinnamonrolls.com"; Group="ClearFake"; Family="ClearFake" },
    @{ Domain="stephanie-bates.com"; Group="ClearFake"; Family="ClearFake" },
    @{ Domain="mulberrylodestar.top"; Group="SmartApeSG"; Family="SmartApeSG" },
    @{ Domain="brewtrail.click"; Group="RevStealer"; Family="RevStealer" },
    @{ Domain="push.brewtrail.click"; Group="RevStealer"; Family="RevStealer" },
    @{ Domain="da.dojiner.at"; Group="Stealer"; Family="ArcaneStealer" },
    @{ Domain="ph.dojiner.at"; Group="Stealer"; Family="ArcaneStealer" },
    @{ Domain="smarwth.biz"; Group="Remus"; Family="RemusStealer" },
    @{ Domain="chrome-windows.ru"; Group="FakeUpdate"; Family="ValleyRAT" },
    @{ Domain="tashirpizza.su"; Group="Malware"; Family="Malware" },
    @{ Domain="livepilates.com.sg"; Group="IClickFix"; Family="IClickFix" },
    @{ Domain="liveproject.fr"; Group="IClickFix"; Family="IClickFix" },
    @{ Domain="lifeisavicnic.com"; Group="IClickFix"; Family="IClickFix" },
    @{ Domain="malware.testcategory.com"; Group="TEST"; Family="Test" },
    @{ Domain="phishing.testcategory.com"; Group="TEST"; Family="Test" },
    @{ Domain="command-and-control.testcategory.com"; Group="TEST"; Family="Test" },
    @{ Domain="testmyids.com"; Group="TEST"; Family="Test" },
    @{ Domain="wicar.org"; Group="TEST"; Family="Test" }
)

function Build-DnsQuery {
    param([string]$Name)
    $ms = New-Object System.IO.MemoryStream
    $ms.WriteByte((Get-Random -Minimum 0 -Maximum 255))
    $ms.WriteByte((Get-Random -Minimum 0 -Maximum 255))
    $ms.Write([byte[]]@(0x01, 0x00), 0, 2)
    $ms.Write([byte[]]@(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), 0, 8)
    foreach ($label in $Name.Split('.')) {
        $ms.WriteByte([byte]$label.Length)
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
        $ms.Write($bytes, 0, $bytes.Length)
    }
    $ms.WriteByte(0x00)
    $ms.Write([byte[]]@(0x00, 0x01), 0, 2)
    $ms.Write([byte[]]@(0x00, 0x01), 0, 2)
    [byte[]]$result = $ms.ToArray()
    $ms.Close()
    return $result
}

function Parse-DnsResponse {
    param([byte[]]$Data)
    if ($Data.Length -lt 12) { return "PARSE-ERROR" }
    $rcode = $Data[3] -band 0x0F
    if ($rcode -eq 3) { return "NXDOMAIN" }
    if ($rcode -ne 0) { return "DNS-ERROR (rcode=$rcode)" }
    $ancount = ([int]$Data[6] -shl 8) + [int]$Data[7]
    if ($ancount -eq 0) { return "NO ANSWERS" }
    $pos = 12
    while ($pos -lt $Data.Length -and $Data[$pos] -ne 0) {
        if (($Data[$pos] -band 0xC0) -eq 0xC0) { $pos += 2; break }
        $pos += $Data[$pos] + 1
    }
    if ($Data[$pos] -eq 0) { $pos++ }
    $pos += 4
    $ips = @()
    for ($i = 0; $i -lt $ancount -and $pos -lt $Data.Length; $i++) {
        if (($Data[$pos] -band 0xC0) -eq 0xC0) { $pos += 2 } else {
            while ($pos -lt $Data.Length -and $Data[$pos] -ne 0) { $pos += $Data[$pos] + 1 }
            $pos++
        }
        if (($pos + 10) -gt $Data.Length) { break }
        $atype = ([int]$Data[$pos] -shl 8) + [int]$Data[$pos+1]
        $rdlen = ([int]$Data[$pos+8] -shl 8) + [int]$Data[$pos+9]
        $pos += 10
        if ($atype -eq 1 -and $rdlen -eq 4 -and ($pos + 4) -le $Data.Length) {
            $ips += "$($Data[$pos]).$($Data[$pos+1]).$($Data[$pos+2]).$($Data[$pos+3])"
        }
        $pos += $rdlen
    }
    if ($ips.Count -gt 0) { return ($ips -join ", ") }
    return "RESOLVED (no A)"
}

function Resolve-DoT {
    param([string]$Name, [string]$Server, [int]$Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($Server, $Port)
        $callback = [System.Net.Security.RemoteCertificateValidationCallback]{ param($s,$c,$ch,$e) return $true }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
        $ssl.AuthenticateAsClient("")

        [byte[]]$query = Build-DnsQuery -Name $Name
        [byte[]]$packet = New-Object byte[] ($query.Length + 2)
        $packet[0] = [byte]([math]::Floor($query.Length / 256))
        $packet[1] = [byte]($query.Length % 256)
        [Array]::Copy($query, 0, $packet, 2, $query.Length)
        $ssl.Write($packet, 0, $packet.Length)
        $ssl.Flush()

        [byte[]]$respLen = New-Object byte[] 2
        $ssl.Read($respLen, 0, 2) | Out-Null
        $totalLen = ([int]$respLen[0] -shl 8) + [int]$respLen[1]
        [byte[]]$respData = New-Object byte[] $totalLen
        $read = 0
        while ($read -lt $totalLen) {
            $r = $ssl.Read($respData, $read, $totalLen - $read)
            if ($r -eq 0) { break }
            $read += $r
        }

        $ssl.Close()
        $tcp.Close()

        return Parse-DnsResponse -Data $respData
    } catch {
        return "DOT-ERROR: $($_.Exception.Message)"
    }
}

$logFile = "ioc_dot_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$resolved = 0; $nxdomain = 0; $errors = 0

Write-Host "[*] IOC DNS-over-TLS Bypass Test"
Write-Host "[*] DoT Server: $DoTServer`:$DoTPort"
Write-Host "[*] Domains: $($domains.Count)"
Write-Host "[*] Transport: TLS/TCP port $DoTPort (bypasses UDP/53 DNS filtering)"
Write-Host ""
Write-Host ("{0,-65} {1,-14} {2,-14} {3}" -f "DOMAIN","GROUP","FAMILY","DoT RESULT")
Write-Host ("=" * 140)

Add-Content -Path $logFile -Value "IOC DoT Bypass Test - $(Get-Date)"
Add-Content -Path $logFile -Value "DoT Server: $DoTServer`:$DoTPort"
Add-Content -Path $logFile -Value ("=" * 140)

foreach ($d in $domains) {
    $result = Resolve-DoT -Name $d.Domain -Server $DoTServer -Port $DoTPort

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

Add-Content -Path $logFile -Value ""
Add-Content -Path $logFile -Value "RESOLVED=$resolved NXDOMAIN=$nxdomain ERRORS=$errors TOTAL=$($domains.Count)"
