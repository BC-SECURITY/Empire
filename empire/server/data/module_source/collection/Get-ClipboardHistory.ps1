function Get-ClipboardHistory() {

    #TODO: add fallback if error (clipboard history might not be enable)

    Add-Type -AssemblyName System.Runtime.WindowsRuntime

    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]

    function Await($WinRtTask, $ResultType) {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(-1) | Out-Null
        $netTask.Result
    }

    $null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType=WindowsRuntime]
    $op = [Windows.ApplicationModel.DataTransfer.Clipboard]::GetHistoryItemsAsync()

    $result = Await ($op) `
        ([Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResult])

    $textops = $result.Items.Content.GetTextAsync()
    for ($i = 0; $i -lt $textops.Count; $i++){ Await($textops[$i]) ([String]) }
}