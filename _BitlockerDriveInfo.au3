#include-once
#include <Array.au3>
#RequireAdmin

; #FUNCTION# ====================================================================================================================
; Name...........: _BitlockerDriveInfo
; Description ...: Get Bitlocker information for one or multiple drives
; Syntax.........: _BitlockerDriveInfo([$sDrive[, $sComputer = @ComputerName[, $bDebug = False]]])
; Parameters ....: $sDrive  - Optional: The drive. Allowed values are:
;                  |""      - Get the info for all available drives
;                  |Letter: - Get the info for the specific drive
;                  $sComputer - Optional: The computer from which the info should be requested
;                  $bDebug  - Optional: Shows the hex ReturnValue from the WMI methods if set to True
; Return values .: Success  - Returns a 2D array with the following information
;                  |[string] Drive Letter
;                  |[string] Drive Label
;                  |[string] Volume Type
;                  |[bool]   Initialized For Protection
;                  |[string] Protection Status
;                  |[string] Lock Status
;                  |[bool]   Auto Unlock Enabled
;                  |[bool]   Auto Unlock Key Stored
;                  |[string] Conversion Status
;                  |[string] Encryption Method
;                  |[int]    Encryption Percentage
;                  |[string] Wiping Status
;                  |[int]    Wiping Percentage
;                  |[array]  Key Protectors (Or [string] "None" if the drive isn't protected)
;                  Failure  - 0, sets @error to:
;                  |1 - There was an issue retrieving the COM object. @extended returns error code from ObjGet
;                  |2 - The specified drive in $Drive doesn't exist
;                  |3 - There was an issue running the WMI query
; Author ........: colombeen
; Modified.......:
; Remarks .......: Requires to be run with admin elevation. Windows Vista or newer!
;                  A BIG THANKS to everyone from the community who contributed!
; Related .......:
; Link ..........: https://www.autoitscript.com/forum/topic/195416-func-bitlocker-drive-info/
; Example .......: #include <Array.au3>
;                  $Header = "Drive Letter|Drive Label|Volume Type|Initialized For Protection|Protection Status|" & _
;                            "Lock Status|Auto Unlock Enabled|Auto Unlock Key Stored|Conversion Status|Encryption " & _
;                            "Method|Encryption Percentage|Wiping Status|Wiping Percentage|Key Protectors"
;                  _ArrayDisplay(_BitlockerDriveInfo(), "Bitlocker Drive Info", "", 64, Default, $Header)
; ===============================================================================================================================
Func _BitlockerDriveInfo($sDrive = "", $sComputer = @ComputerName, $bDebug = False)
    Local $aConversionStatusMsg[7]  =   ["Unknown", "Fully Decrypted", "Fully Encrypted", "Encryption In Progress", "Decryption In Progress", "Encryption Paused", "Decryption Paused"]
    Local $aEncryptionMethodMsg[9]  =   ["Unknown", "None", "AES_128_WITH_DIFFUSER", "AES_256_WITH_DIFFUSER", "AES_128", "AES_256", "HARDWARE_ENCRYPTION", "XTS_AES_128", "XTS_AES_256"]
    Local $aKeyProtectorTypeMsg[11] =   ["Unknown or other protector type", "Trusted Platform Module (TPM)", "External key", "Numerical password", "TPM And PIN", "TPM And Startup Key", "TPM And PIN And Startup Key", "Public Key", "Passphrase", "TPM Certificate", "CryptoAPI Next Generation (CNG) Protector"]
    Local $aLockStatusMsg[3]        =   ["Unknown", "Unlocked", "Locked"]
    Local $aProtectionStatusMsg[3]  =   ["Unprotected", "Protected", "Unknown"]
    Local $aVolumeTypeMsg[3]        =   ["Operating System Volume", "Fixed Data Volume", "Portable Data Volume"]
    Local $aWipingStatusMsg[5]      =   ["Unknown", "Free Space Not Wiped", "Free Space Wiped", "Free Space Wiping In Progress", "Free Space Wiping Paused"]
    Local $iRow                     =   0
    Local $sRunMethod, $objWMIService, $objWMIQuery, $sDriveFilter, $iProtectionStatus, $iLockStatus, $bIsAutoUnlockEnabled, $bIsAutoUnlockKeyStored, $iConversionStatus, $iEncryptionPercentage, $iEncryptionFlags, $iWipingStatus, $iWipingPercentage, $iEncryptionMethod, $aVolumeKeyProtectorID, $aVolumeKeyProtectors, $iKeyProtectorType

    $objWMIService = ObjGet("winmgmts:{impersonationLevel=impersonate,authenticationLevel=pktPrivacy}!\\" & $sComputer & "\root\CIMV2\Security\MicrosoftVolumeEncryption")
    If @error Then Return SetError(1, @error, 0)

    If $sDrive <> "" Then
        If Not FileExists($sDrive & "\") Then Return SetError(2, 1, 0)
        If Not (DriveGetType($sDrive) = "Fixed") And Not (DriveGetType($sDrive) = "Removable") Then Return SetError(2, 2, 0)
        $sDriveFilter = " WHERE DriveLetter='" & $sDrive & "'"
    EndIf

    $objWMIQuery = $objWMIService.ExecQuery("SELECT * FROM Win32_EncryptableVolume" & $sDriveFilter, "WQL", 0)
    If Not IsObj($objWMIQuery) Then Return SetError(3, 0, 0)

    Local $aResult[$objWMIQuery.count][14]
    For $objDrive In $objWMIQuery
        If $bDebug Then ConsoleWrite(@CRLF & "+> " & $objDrive.DriveLetter & @CRLF)
        If _WMIMethodExists($objDrive, "GetConversionStatus") Then
            $sRunMethod = $objDrive.GetConversionStatus($iConversionStatus, $iEncryptionPercentage, $iEncryptionFlags, $iWipingStatus, $iWipingPercentage)
            If $bDebug Then ConsoleWrite("!> GetConversionStatus    0x" & Hex($sRunMethod) & @CRLF)
        Else
            $iConversionStatus      =   -1
            $iWipingStatus          =   -1
            $iEncryptionPercentage  =   0
            $iWipingPercentage      =   0
        EndIf
        If _WMIMethodExists($objDrive, "GetEncryptionMethod") Then
            $sRunMethod = $objDrive.GetEncryptionMethod($iEncryptionMethod)
            If $bDebug Then ConsoleWrite("!> GetEncryptionMethod    0x" & Hex($sRunMethod) & @CRLF)
        Else
            $iEncryptionMethod      =   0
        EndIf
        If _WMIMethodExists($objDrive, "GetKeyProtectors") Then
            $sRunMethod = $objDrive.GetKeyProtectors("0", $aVolumeKeyProtectorID)
            If $bDebug Then ConsoleWrite("!> GetKeyProtectors       0x" & Hex($sRunMethod) & @CRLF)
        Else
            $aVolumeKeyProtectorID  =   0
        EndIf
        If _WMIMethodExists($objDrive, "GetLockStatus") Then
            $sRunMethod = $objDrive.GetLockStatus($iLockStatus)
            If $bDebug Then ConsoleWrite("!> GetLockStatus          0x" & Hex($sRunMethod) & @CRLF)
        Else
            $iLockStatus            =   -1
        EndIf
        If _WMIMethodExists($objDrive, "GetProtectionStatus") Then
            $sRunMethod = $objDrive.GetProtectionStatus($iProtectionStatus)
            If $bDebug Then ConsoleWrite("!> GetProtectionStatus    0x" & Hex($sRunMethod) & @CRLF)
        Else
            $iProtectionStatus      =   2
        EndIf
        If _WMIMethodExists($objDrive, "IsAutoUnlockEnabled") Then
            $sRunMethod = $objDrive.IsAutoUnlockEnabled($bIsAutoUnlockEnabled)
            If $bDebug Then ConsoleWrite("!> IsAutoUnlockEnabled    0x" & Hex($sRunMethod) & @CRLF)
        Else
            $bIsAutoUnlockEnabled   =   "Unknown"
        EndIf
        If _WMIMethodExists($objDrive, "IsAutoUnlockKeyStored") Then
            $sRunMethod = $objDrive.IsAutoUnlockKeyStored($bIsAutoUnlockKeyStored)
            If $bDebug Then ConsoleWrite("!> IsAutoUnlockKeyStored  0x" & Hex($sRunMethod) & @CRLF)
        Else
            $bIsAutoUnlockKeyStored =   "Unknown"
        EndIf

        If IsArray($aVolumeKeyProtectorID) And UBound($aVolumeKeyProtectorID) > 0 Then
            Dim $aVolumeKeyProtectors[UBound($aVolumeKeyProtectorID)][2]

            For $i = 0 To UBound($aVolumeKeyProtectorID) - 1
                $aVolumeKeyProtectors[$i][0]        =   $aVolumeKeyProtectorID[$i]
                If _WMIMethodExists($objDrive, "GetKeyProtectorType") Then
                    If $objDrive.GetKeyProtectorType($aVolumeKeyProtectorID[$i], $iKeyProtectorType) = 0 Then
                        $aVolumeKeyProtectors[$i][1]=   $aKeyProtectorTypeMsg[$iKeyProtectorType]
                    Else
                        $aVolumeKeyProtectors[$i][1]=   "Unknown"
                    EndIf
                Else
                    $aVolumeKeyProtectors[$i][1]    =   "Unknown"
                EndIf
            Next
        Else
            $aVolumeKeyProtectors                   =   "None"
        EndIf

        ; DriveLetter
        $aResult[$iRow][0]      =   $objDrive.DriveLetter
        ; DriveLabel
        $aResult[$iRow][1]      =   _WMIPropertyValue("VolumeName", "Win32_LogicalDisk", "WHERE DeviceID='" & $objDrive.DriveLetter & "'", Default, $sComputer)
        ; VolumeType
        If _WMIPropertyExists($objDrive, "VolumeType") Then
            $aResult[$iRow][2]  =   $aVolumeTypeMsg[$objDrive.VolumeType]
        Else
            If $objDrive.DriveLetter = _WMIPropertyValue("SystemDrive", "Win32_OperatingSystem", "", Default, $sComputer) Then
                $aResult[$iRow][2]= $aVolumeTypeMsg[0]
            ElseIf _WMIPropertyValue("DriveType", "Win32_LogicalDisk", "WHERE DeviceID='" & $objDrive.DriveLetter & "'", Default, $sComputer) = 3 Then
                $aResult[$iRow][2]= $aVolumeTypeMsg[1]
            ElseIf _WMIPropertyValue("DriveType", "Win32_LogicalDisk", "WHERE DeviceID='" & $objDrive.DriveLetter & "'", Default, $sComputer) = 2 Then
                $aResult[$iRow][2]= $aVolumeTypeMsg[2]
            Else
                $aResult[$iRow][2]= "Unknown"
            EndIf
        EndIf
        ; IsVolumeInitializedForProtection
        If _WMIPropertyExists($objDrive, "IsVolumeInitializedForProtection") Then
            $aResult[$iRow][3]  =   $objDrive.IsVolumeInitializedForProtection
        Else
            $aResult[$iRow][3]  =   "Unkown"
        EndIf
        ; ProtectionStatus
        $aResult[$iRow][4]      =   $aProtectionStatusMsg[$iProtectionStatus]
        ; LockStatus
        $aResult[$iRow][5]      =   $aLockStatusMsg[$iLockStatus + 1]
        ; IsAutoUnlockEnabled
        $aResult[$iRow][6]      =   $bIsAutoUnlockEnabled
        ; IsAutoUnlockEnabled
        $aResult[$iRow][7]      =   $bIsAutoUnlockKeyStored
        ; ConversionStatus
        $aResult[$iRow][8]      =   $aConversionStatusMsg[$iConversionStatus + 1]
        ; EncryptionMethod
        $aResult[$iRow][9]      =   $aEncryptionMethodMsg[$iEncryptionMethod + 1]
        ; EncryptionPercentage
        $aResult[$iRow][10]     =   $iEncryptionPercentage
        ; WipingStatus
        $aResult[$iRow][11]     =   $aWipingStatusMsg[$iWipingStatus + 1]
        ; WipingPercentage
        $aResult[$iRow][12]     =   $iWipingPercentage
        ; KeyProtectors
        $aResult[$iRow][13]     =   $aVolumeKeyProtectors

        $iRow += 1
    Next
    _ArraySort($aResult)
    Return $aResult
EndFunc   ;==>_BitlockerDriveInfo

Func _WMIPropertyExists($Object, $Property)
    If Not IsObj($Object) Then Return False
    For $sProperty In $Object.Properties_
        If $sProperty.Name = $Property Then Return True
    Next
    Return False
EndFunc   ;==>_WMIPropertyExists

Func _WMIMethodExists($Object, $Method)
    If Not IsObj($Object) Then Return False
    For $sMethod In $Object.Methods_
        If $sMethod.Name = $Method Then Return True
    Next
    Return False
EndFunc   ;==>_WMIMethodExists

Func _WMIPropertyValue($sProperty = "", $sClass = "", $sFilter = "", $sNamespace = Default, $sComputer = @ComputerName)
    Local $objWMIService, $objWMIQuery

    If $sClass = "" Or $sProperty = "" Then Return SetError(1, 0, 0)
    If $sFilter <> "" Then $sFilter = " " & $sFilter
    If $sNamespace = Default Then $sNamespace = "\root\CIMV2"

    $objWMIService = ObjGet("winmgmts:{impersonationLevel=impersonate,authenticationLevel=pktPrivacy}!\\" & $sComputer & $sNamespace)
    If @error Then Return SetError(2, @error, 0)

    $objWMIQuery = $objWMIService.ExecQuery("SELECT " & $sProperty & " FROM " & $sClass & $sFilter, "WQL", 0x30)
    If Not IsObj($objWMIQuery) Then Return SetError(3, 0, 0)

    For $objItem In $objWMIQuery
        For $Property In $objItem.Properties_
            If $Property.Name = $sProperty Then
                Return $Property.Value
            EndIf
        Next
    Next

    Return SetError(4, 0, 0)
EndFunc   ;==>_WMIPropertyValue