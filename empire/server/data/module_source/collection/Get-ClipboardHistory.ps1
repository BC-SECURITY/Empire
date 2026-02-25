function Get-ClipboardHistory {

    $ErrorActionPreference = 'Stop'

    function Fail($msg) { throw $msg }

    Add-Type -AssemblyName System.Runtime.WindowsRuntime

    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object {
            $_.Name -eq 'AsTask' -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
        })[0]

    function Await($WinRtTask, $ResultType) {
        $asTask  = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $null = $netTask.Wait(-1)
        $netTask.Result
    }

    $null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType=WindowsRuntime]

    $result = Await (
        [Windows.ApplicationModel.DataTransfer.Clipboard]::GetHistoryItemsAsync()
    ) ([Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResult])

    if ($result.Status -ne [Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResultStatus]::Success) {
        Fail "ClipboardHistory is not accessible, it might not be enabled. Status: $($result.Status)"
    }

    try {

        $textOps = $result.Items.Content.GetTextAsync()

        $out = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $textOps.Count; $i++) {
            $txt = Await ($textOps[$i]) ([string])
            if ($txt) { $out.Add("---`n$txt") }
        }

        Write-Output $out

    } catch {
        Fail "Clipboard is empty."
    }
}
