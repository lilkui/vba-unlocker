Option Explicit

Private Const PAGE_EXECUTE_READWRITE = &H40
Private Const OPCODE_PUSH = &H68
Private Const OPCODE_RETN = &HC3

Private Declare PtrSafe Sub MoveMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As LongPtr, Source As LongPtr, ByVal Length As LongPtr)
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flNewProtect As LongPtr, lpflOldProtect As LongPtr) As LongPtr
Private Declare PtrSafe Function GetModuleHandle Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As LongPtr
Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function DialogBoxParam Lib "user32" Alias "DialogBoxParamA" (ByVal hInstance As LongPtr, ByVal pTemplateName As LongPtr, ByVal hWndParent As LongPtr, ByVal lpDialogFunc As LongPtr, ByVal dwInitParam As LongPtr) As Integer

Dim NewOpCodes(0 To 5) As Byte
Dim OldOpCodes(0 To 5) As Byte
Dim PfDialogBoxParam As LongPtr
Dim IsHooked As Boolean

Private Function GetPtr(ByVal Value As LongPtr) As LongPtr
    GetPtr = Value
End Function

Private Function FakeDialogBoxParam(ByVal hInstance As LongPtr, ByVal pTemplateName As LongPtr, ByVal hWndParent As LongPtr, ByVal lpDialogFunc As LongPtr, ByVal dwInitParam As LongPtr) As Integer
    If pTemplateName = 4070 Then
        FakeDialogBoxParam = 1
    Else
        Unhook
        FakeDialogBoxParam = DialogBoxParam(hInstance, pTemplateName, hWndParent, lpDialogFunc, dwInitParam)
        Hook
    End If
End Function

Public Function Hook() As Boolean
    Dim TempOpCodes(0 To 5) As Byte
    Dim PfFakeDialogBoxParam As LongPtr
    Dim OldProtect As LongPtr

    Hook = False
    PfDialogBoxParam = GetProcAddress(GetModuleHandle("user32.dll"), "DialogBoxParamA")
    If VirtualProtect(ByVal PfDialogBoxParam, 6, PAGE_EXECUTE_READWRITE, OldProtect) <> 0 Then
        MoveMemory ByVal VarPtr(TempOpCodes(0)), ByVal PfDialogBoxParam, 6
        If TempOpCodes(0) <> OPCODE_PUSH Then
            MoveMemory ByVal VarPtr(OldOpCodes(0)), ByVal PfDialogBoxParam, 6
            PfFakeDialogBoxParam = GetPtr(AddressOf FakeDialogBoxParam)
            NewOpCodes(0) = OPCODE_PUSH
            MoveMemory ByVal VarPtr(NewOpCodes(1)), ByVal VarPtr(PfFakeDialogBoxParam), 4
            NewOpCodes(5) = OPCODE_RETN
            MoveMemory ByVal PfDialogBoxParam, ByVal VarPtr(NewOpCodes(0)), 6
            IsHooked = True
            Hook = True
        End If
    End If
End Function

Public Sub Unhook()
    If IsHooked Then MoveMemory ByVal PfDialogBoxParam, ByVal VarPtr(OldOpCodes(0)), 6
End Sub

Sub BypassProtection()
    If Hook Then
        MsgBox "VBA password protection has been bypassed successfully.", vbInformation, "VBA Protection Bypasser"
    End If
End Sub
