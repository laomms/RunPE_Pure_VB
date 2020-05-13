Imports System.Runtime.InteropServices
Imports System.Security

Module pinvoke
    Public Const PROCESS_ALL_ACCESS = &H1F0FF
    Public Const PROCESS_VM_OPERATION As UInteger = &H8
    Public Const PROCESS_VM_WRITE As UInteger = &H20
    Public Const PROCESS_VM_READ As UInteger = &H10
    Public Const PAGE_EXECUTE_READWRITE As UInteger = &H40
    Public Const MEM_COMMIT As Long = &H1000
    Public Const MEM_RESERVE As Long = &H2000
    Public Structure PROCESS_INFORMATION
        Public hProcess As IntPtr
        Public hThread As IntPtr
        Public dwProcessId As UInteger
        Public dwThreadId As UInteger
    End Structure
    Public Structure STARTUPINFO
        Public cb As UInteger
        Public lpReserved As String
        Public lpDesktop As String
        Public lpTitle As String
        Public dwX As UInteger
        Public dwY As UInteger
        Public dwXSize As UInteger
        Public dwYSize As UInteger
        Public dwXCountChars As UInteger
        Public dwYCountChars As UInteger
        Public dwFillAttribute As UInteger
        Public dwFlags As UInteger
        Public wShowWindow As Short
        Public cbReserved2 As Short
        Public lpReserved2 As IntPtr
        Public hStdInput As IntPtr
        Public hStdOutput As IntPtr
        Public hStdError As IntPtr
    End Structure
    <DllImport("kernel32.dll", EntryPoint:="CreateProcessA")>
    Public Function CreateProcess(ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As IntPtr, ByVal lpThreadAttributes As IntPtr, ByVal bInheritHandles As Boolean, ByVal dwCreationFlags As UInteger, ByVal lpEnvironment As IntPtr, ByVal lpCurrentDirectory As String, ByRef lpStartupInfo As STARTUPINFO, ByRef lpProcessInformation As PROCESS_INFORMATION) As Boolean
    End Function
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_DOS_HEADER
        Public e_magic As UInt16
        Public e_cblp As UInt16
        Public e_cp As UInt16
        Public e_crlc As UInt16
        Public e_cparhdr As UInt16
        Public e_minalloc As UInt16
        Public e_maxalloc As UInt16
        Public e_ss As UInt16
        Public e_sp As UInt16
        Public e_csum As UInt16
        Public e_ip As UInt16
        Public e_cs As UInt16
        Public e_lfarlc As UInt16
        Public e_ovno As UInt16
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=4)>
        Public e_res1 As UInt16()
        Public e_oemid As UInt16
        Public e_oeminfo As UInt16
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=10)>
        Public e_res2 As UInt16()
        Public e_lfanew As Int32
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_FILE_HEADER
        Public Machine As UShort                        '标识CPU的数字。运行平台。
        Public NumberOfSections As UShort               '节的数目。Windows加载器限制节的最大数目为96。文件区块数目。
        Public TimeDateStamp As UInteger                '文件创建日期和时间,UTC时间1970年1月1日00:00起的总秒数的低32位。
        Public PointerToSymbolTable As UInteger         '指向符号表（主要用于调试）,已废除。
        Public NumberOfSymbols As UInteger              '符号表中符号个数，已废除。
        Public SizeOfOptionalHeader As UShort           'IMAGE_OPTIONAL_HEADER32 结构大小，可选头大小。
        Public Characteristics As UShort                '文件属性，文件特征值。
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_NT_HEADERS32
        Public Signature As UInteger                        '4   ubytes PE文件头标志：(e_lfanew)->‘PE\0\0’
        Public FileHeader As IMAGE_FILE_HEADER              '20  ubytes PE文件物理分布的信息
        Public OptionalHeader As IMAGE_OPTIONAL_HEADER32    '224 ubytes PE文件逻辑分布的信息
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_NT_HEADERS64
        Public Signature As UInteger                        '4   ubytes PE文件头标志：(e_lfanew)->‘PE\0\0’
        Public FileHeader As IMAGE_FILE_HEADER              '20  ubytes PE文件物理分布的信息
        Public OptionalHeader As IMAGE_OPTIONAL_HEADER64    '224 ubytes PE文件逻辑分布的信息
    End Structure

    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_OPTIONAL_HEADER32
        Public Magic As UShort                           ' 标志字, 0x0107表明这是一个ROM 映像,0x10B表明这是一个32位镜像文件。，0x20B表明这是一个64位镜像文件。
        Public MajorLinkerVersion As Byte                ' 链接程序的主版本号
        Public MinorLinkerVersion As Byte                ' 链接程序的次版本号
        Public SizeOfCode As UInteger                    ' 所有含代码的节的总大小
        Public SizeOfInitializedData As UInteger         ' 所有含已初始化数据的节的总大小
        Public SizeOfUninitializedData As UInteger       ' 所有含未初始化数据的节的大小
        Public AddressOfEntryPoint As UInteger           ' 程序执行入口RVA
        Public BaseOfCode As UInteger                    ' 代码的区块的起始RVA
        Public BaseOfData As UInteger                    ' 数据的区块的起始RVA
        Public ImageBase As UInteger                     ' 程序的首选装载地址
        Public SectionAlignment As UInteger              ' 内存中的区块的对齐大小
        Public FileAlignment As UInteger                 ' 文件中的区块的对齐大小
        Public MajorOperatingSystemVersion As UShort     ' 要求操作系统最低版本号的主版本号
        Public MinorOperatingSystemVersion As UShort     ' 要求操作系统最低版本号的副版本号
        Public MajorImageVersion As UShort               ' 可运行于操作系统的主版本号
        Public MinorImageVersion As UShort               ' 可运行于操作系统的次版本号
        Public MajorSubsystemVersion As UShort           ' 要求最低子系统版本的主版本号
        Public MinorSubsystemVersion As UShort           ' 要求最低子系统版本的次版本号
        Public Win32VersionValue As UInteger             ' 莫须有字段，不被病毒利用的话一般为0
        Public SizeOfImage As UInteger                   ' 映像装入内存后的总尺寸
        Public SizeOfHeaders As UInteger                 ' 所有头 + 区块表的尺寸大小
        Public CheckSum As UInteger                      ' 映像的校检和
        Public Subsystem As UShort                       ' 可执行文件期望的子系统
        Public DllCharacteristics As UShort              ' DllMain()函数何时被调用，默认为 0
        Public SizeOfStackReserve As UInteger            ' 初始化时的栈大小
        Public SizeOfStackCommit As UInteger             ' 初始化时实际提交的栈大小
        Public SizeOfHeapReserve As UInteger             ' 初始化时保留的堆大小
        Public SizeOfHeapCommit As UInteger              ' 初始化时实际提交的堆大小
        Public LoaderFlags As UInteger                   ' 与调试有关，默认为 0 
        Public NumberOfRvaAndSizes As UInteger           ' 下边数据目录的项数，这个字段自Windows NT 发布以来一直是16
        Public IMAGE_DIRECTORY_ENTRY_EXPORT As IMAGE_DATA_DIRECTORY         '导出表
        Public IMAGE_DIRECTORY_ENTRY_IMPORT As IMAGE_DATA_DIRECTORY         '导入表
        Public IMAGE_DIRECTORY_ENTRY_RESOURCE As IMAGE_DATA_DIRECTORY       '资源目录
        Public IMAGE_DIRECTORY_ENTRY_EXCEPTION As IMAGE_DATA_DIRECTORY      '异常目录
        Public IMAGE_DIRECTORY_ENTRY_SECURITY As IMAGE_DATA_DIRECTORY       '安全目录
        Public IMAGE_DIRECTORY_ENTRY_BASERELOC As IMAGE_DATA_DIRECTORY      '重定位基本表
        Public IMAGE_DIRECTORY_ENTRY_DEBUG As IMAGE_DATA_DIRECTORY          '调试目录
        Public IMAGE_DIRECTORY_ENTRY_COPYRIGHT As IMAGE_DATA_DIRECTORY      '描述字符串
        Public IMAGE_DIRECTORY_ENTRY_ARCHITECTURE As IMAGE_DATA_DIRECTORY   '机器值
        Public IMAGE_DIRECTORY_ENTRY_GLOBALPTR As IMAGE_DATA_DIRECTORY      '线程本地存储
        Public IMAGE_DIRECTORY_ENTRY_TLS As IMAGE_DATA_DIRECTORY            'TLS目录
        Public IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG As IMAGE_DATA_DIRECTORY    '载入配置目录
        Public IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT As IMAGE_DATA_DIRECTORY   '绑定倒入表
        Public IMAGE_DIRECTORY_ENTRY_IAT As IMAGE_DATA_DIRECTORY            '导入地址表
        Public IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT As IMAGE_DATA_DIRECTORY   '延迟倒入表
        Public IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR As IMAGE_DATA_DIRECTORY 'COM描述符
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_OPTIONAL_HEADER64
        Public Magic As UShort                           ' 标志字, 0x0107表明这是一个ROM 映像,0x10B表明这是一个32位镜像文件。，0x20B表明这是一个64位镜像文件。
        Public MajorLinkerVersion As Byte                ' 链接程序的主版本号
        Public MinorLinkerVersion As Byte                ' 链接程序的次版本号
        Public SizeOfCode As UInteger                    ' 所有含代码的节的总大小
        Public SizeOfInitializedData As UInteger         ' 所有含已初始化数据的节的总大小
        Public SizeOfUninitializedData As UInteger       ' 所有含未初始化数据的节的大小
        Public AddressOfEntryPoint As UInteger           ' 程序执行入口RVA
        Public BaseOfCode As UInteger                    ' 代码的区块的起始RVA
        'Public BaseOfData As UInteger                    ' 数据的区块的起始RVA
        Public ImageBase As UInteger                     ' 程序的首选装载地址
        Public SectionAlignment As UInteger              ' 内存中的区块的对齐大小
        Public FileAlignment As UInteger                 ' 文件中的区块的对齐大小
        Public MajorOperatingSystemVersion As UShort     ' 要求操作系统最低版本号的主版本号
        Public MinorOperatingSystemVersion As UShort     ' 要求操作系统最低版本号的副版本号
        Public MajorImageVersion As UShort               ' 可运行于操作系统的主版本号
        Public MinorImageVersion As UShort               ' 可运行于操作系统的次版本号
        Public MajorSubsystemVersion As UShort           ' 要求最低子系统版本的主版本号
        Public MinorSubsystemVersion As UShort           ' 要求最低子系统版本的次版本号
        Public Win32VersionValue As UInteger             ' 莫须有字段，不被病毒利用的话一般为0
        Public SizeOfImage As UInteger                   ' 映像装入内存后的总尺寸
        Public SizeOfHeaders As UInteger                 ' 所有头 + 区块表的尺寸大小
        Public CheckSum As UInteger                      ' 映像的校检和
        Public Subsystem As UShort                       ' 可执行文件期望的子系统
        Public DllCharacteristics As UShort              ' DllMain()函数何时被调用，默认为 0
        Public SizeOfStackReserve As ULong            ' 初始化时的栈大小
        Public SizeOfStackCommit As ULong             ' 初始化时实际提交的栈大小
        Public SizeOfHeapReserve As ULong             ' 初始化时保留的堆大小
        Public SizeOfHeapCommit As ULong              ' 初始化时实际提交的堆大小
        Public LoaderFlags As UInteger                   ' 与调试有关，默认为 0 
        Public NumberOfRvaAndSizes As UInteger           ' 下边数据目录的项数，这个字段自Windows NT 发布以来一直是16
        Public IMAGE_DIRECTORY_ENTRY_EXPORT As IMAGE_DATA_DIRECTORY         '导出函数表
        Public IMAGE_DIRECTORY_ENTRY_IMPORT As IMAGE_DATA_DIRECTORY         '导入函数表
        Public IMAGE_DIRECTORY_ENTRY_RESOURCE As IMAGE_DATA_DIRECTORY       '资源目录
        Public IMAGE_DIRECTORY_ENTRY_EXCEPTION As IMAGE_DATA_DIRECTORY      '异常目录
        Public IMAGE_DIRECTORY_ENTRY_SECURITY As IMAGE_DATA_DIRECTORY       '安全目录
        Public IMAGE_DIRECTORY_ENTRY_BASERELOC As IMAGE_DATA_DIRECTORY      '重定位基本表
        Public IMAGE_DIRECTORY_ENTRY_DEBUG As IMAGE_DATA_DIRECTORY          '调试目录
        Public IMAGE_DIRECTORY_ENTRY_COPYRIGHT As IMAGE_DATA_DIRECTORY      '描述字符串
        Public IMAGE_DIRECTORY_ENTRY_ARCHITECTURE As IMAGE_DATA_DIRECTORY   '机器值
        Public IMAGE_DIRECTORY_ENTRY_GLOBALPTR As IMAGE_DATA_DIRECTORY      '线程本地存储
        Public IMAGE_DIRECTORY_ENTRY_TLS As IMAGE_DATA_DIRECTORY            'TLS目录
        Public IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG As IMAGE_DATA_DIRECTORY    '载入配置目录
        Public IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT As IMAGE_DATA_DIRECTORY   '绑定入口
        Public IMAGE_DIRECTORY_ENTRY_IAT As IMAGE_DATA_DIRECTORY            '导入地址表
        Public IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT As IMAGE_DATA_DIRECTORY   '延迟入口
        Public IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR As IMAGE_DATA_DIRECTORY 'COM描述符
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_DATA_DIRECTORY
        Public VirtualAddress As UInteger      '地址
        Public Size As UInteger                '大小
    End Structure
    Public Structure Misc
        Public PhysicalAddress As System.UInt32
        Public VirtualSize As System.UInt32
    End Structure
    Public Structure IMAGE_SECTION_HEADER
        Public Name As System.Byte
        Public Misc As Misc
        Public VirtualAddress As System.UInt32
        Public SizeOfRawData As System.UInt32
        Public PointerToRawData As System.UInt32
        Public PointerToRelocations As System.UInt32
        Public PointerToLinenumbers As System.UInt32
        Public NumberOfRelocations As System.UInt16
        Public NumberOfLinenumbers As System.UInt16
        Public Characteristics As System.UInt32
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_EXPORT_DIRECTORY
        Public Characteristics As UInteger             '未使用,为0
        Public TimeDateStamp As UInteger               '文件生成时间
        Public MajorVersion As UShort                  '未使用,为0
        Public MinorVersion As UShort                  '未使用,为0
        Public Name As UInteger                        '这是这个PE文件的模块名
        Public Base As UInteger                        '基数，加上序数就是函数地址数组的索引值
        Public NumberOfFunctions As UInteger           '导出函数的个数
        Public NumberOfNames As UInteger               '以名称方式导出的函数的总数（有的函数没有名称只有序数）
        Public AddressOfFunctions As UInteger          'RVA from base of image Nt头基址加上这个偏移得到的数组中存放所有的导出地址表
        Public AddressOfNames As UInteger              'RVA from base of image Nt头基址加上这个偏移得到的数组中存放所有的名称字符串
        Public AddressOfNameOrdinals As UInteger       'RVA from base of image Nt头基址加上这个偏移得到的数组中存放所有的函数序号，并不一定是连续的，但一般和导出地址表是一一对应的
    End Structure
    <StructLayout(LayoutKind.Explicit)>
    Public Structure IMAGE_THUNK_DATA32
        <FieldOffset(0)> Public ForwarderString As UInteger
        <FieldOffset(0)> Public [Function] As UInteger
        <FieldOffset(0)> Public Ordinal As UInteger
        <FieldOffset(0)> Public AddressOfData As UInteger
    End Structure
    Public Structure IMAGE_IMPORT_DESCRIPTOR
        Public OriginalFirstThunk As UInteger
        Public TimeDateStamp As UInteger
        Public ForwarderChain As UInteger
        Public Name As UInteger
        Public FirstThunk As UInteger
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_IMPORT_BY_NAME
        Public Hint As Short
        Public Name As Byte
    End Structure
    <DllImport("dbghelp", SetLastError:=True)>
    Public Function ImageRvaToVa(ByVal NtHeaders As IntPtr, ByVal Base As IntPtr, ByVal Rva As UInteger, ByVal LastRvaSection As Integer) As IntPtr
    End Function

    <DllImport("ntdll")>
    Public Function NtUnmapViewOfSection(ByVal hProc As IntPtr, ByVal baseAddr As IntPtr) As UInteger
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, ExactSpelling:=True)>
    Public Function VirtualAllocEx(ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As IntPtr, ByVal flAllocationType As UInteger, ByVal flProtect As UInteger) As IntPtr
    End Function
    <DllImport("kernel32.dll", SetLastError:=True)>
    Public Function TerminateProcess(ByVal hProcess As IntPtr, ByVal uExitCode As UInteger) As Boolean
    End Function
    <DllImport("kernel32.dll")>
    Public Function ResumeThread(hThread As IntPtr) As UInt32
    End Function
    <DllImport("kernel32.dll", SetLastError:=True)>
    Public Function CloseHandle(ByVal hObject As IntPtr) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True)>
    Public Function WriteProcessMemory(ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal lpBuffer As IntPtr, ByVal nSize As Int32, ByRef lpNumberOfBytesWritten As IntPtr) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True)>
    Public Function WriteProcessMemory(ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal lpBuffer() As Byte, ByVal nSize As Integer, ByRef lpNumberOfBytesWritten As IntPtr) As Boolean
    End Function
    Public Enum ProcessAccessFlags As UInteger
        All = &H1F0FFF
        Terminate = &H1
        CreateThread = &H2
        VirtualMemoryOperation = &H8
        VirtualMemoryRead = &H10
        VirtualMemoryWrite = &H20
        DuplicateHandle = &H40
        CreateProcess = &H80
        SetQuota = &H100
        SetInformation = &H200
        QueryInformation = &H400
        QueryLimitedInformation = &H1000
        Synchronize = &H100000
    End Enum
    <DllImport("kernel32.dll")>
    Public Function OpenProcess(ByVal dwDesiredAccess As ProcessAccessFlags, <MarshalAs(UnmanagedType.Bool)> ByVal bInheritHandle As Boolean, ByVal dwProcessId As Integer) As IntPtr
    End Function
    Public Enum CONTEXT_FLAGS As UInteger
        CONTEXT_i386 = &H10000
        CONTEXT_i486 = &H10000
        CONTEXT_CONTROL = CONTEXT_i386 Or &H1
        CONTEXT_INTEGER = CONTEXT_i386 Or &H2
        CONTEXT_SEGMENTS = CONTEXT_i386 Or &H4
        CONTEXT_FLOATING_POINT = CONTEXT_i386 Or &H8
        CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 Or &H10
        CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 Or &H20
        CONTEXT_FULL = CONTEXT_CONTROL Or CONTEXT_INTEGER Or CONTEXT_SEGMENTS
        CONTEXT_ALL = CONTEXT_CONTROL Or CONTEXT_INTEGER Or CONTEXT_SEGMENTS Or CONTEXT_FLOATING_POINT Or CONTEXT_DEBUG_REGISTERS Or CONTEXT_EXTENDED_REGISTERS
    End Enum
    <StructLayout(LayoutKind.Sequential)>
    Structure FLOATING_SAVE_AREA
        Dim Control, Status, Tag, ErrorO, ErrorS, DataO, DataS As UInteger
        <System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst:=80)> Dim RegisterArea As Byte()
        Dim State As UInteger
    End Structure

    <StructLayout(LayoutKind.Sequential)>
    Structure CONTEXT32
        Dim ContextFlags, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7 As UInteger
        Dim FloatSave As FLOATING_SAVE_AREA
        Dim SegGs, SegFs, SegEs, SegDs, Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp, Eip, SegCs, EFlags, Esp, SegSs As UInteger
        <System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst:=512)> Dim ExtendedRegisters As Byte()
    End Structure

    <StructLayout(LayoutKind.Sequential, Pack:=16)>
    Structure M128A
        Dim Low As ULong
        Dim High As Long
    End Structure

    <StructLayout(LayoutKind.Sequential, Pack:=16)>
    Structure CONTEXT64
        Dim P1Home, P2Home, P3Home, P4Home, P5Home, P6Home As ULong
        Dim ContextFlags, MxCsr As UInteger
        Dim SegCs, SegDs, SegEs, SegFs, SegGs, SegSs As UShort
        Dim EFlags As UInteger
        Dim Dr0, Dr1, Dr2, Dr3, Dr6, Dr7, Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip As UInteger
        <System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPArray, SizeConst:=2)> Dim Header As M128A()
        <System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPArray, SizeConst:=8)> Dim Legacy As M128A()
        Dim Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6, Xmm7, Xmm8, Xmm9, Xmm10, Xmm11, Xmm12, Xmm13, Xmm14, Xmm15 As M128A
        <System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPArray, SizeConst:=26)> Dim VectorRegister As M128A()
        Dim VectorControl, DebugControl, LastBranchToRip, LastBranchFromRip, LastExceptionToRip, LastExceptionFromRip As UInteger
    End Structure

    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="GetThreadContext")>
    Public Function GetThreadContext32(ByVal hThread As IntPtr, ByRef lpContext As CONTEXT32) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="SetThreadContext")>
    Public Function SetThreadContext32(ByVal hThread As IntPtr, ByRef lpContext As CONTEXT32) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="GetThreadContext")>
    Public Function GetThreadContext64(ByVal hThread As IntPtr, ByRef lpContext As CONTEXT64) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="SetThreadContext")>
    Public Function SetThreadContext64(ByVal hThread As IntPtr, ByRef lpContext As CONTEXT64) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="Wow64GetThreadContext")>
    Public Function Wow64GetThreadContext32(ByVal hThread As IntPtr, ByRef lpContext As CONTEXT32) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="Wow64SetThreadContext")>
    Public Function Wow64SetThreadContext32(ByVal hThread As IntPtr, ByRef lpContext As CONTEXT32) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="Wow64GetThreadContext")>
    Public Function Wow64GetThreadContext64(ByVal hThread As IntPtr, ByRef lpContext As CONTEXT64) As Boolean
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="Wow64SetThreadContext")>
    Public Function Wow64SetThreadContext64(ByVal hThread As IntPtr, ByRef lpContext As CONTEXT64) As Boolean
    End Function

    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="IsWow64Process")>
    Public Function IsWow64Process(ByVal hProcess As IntPtr, ByRef Wow64Process As Boolean) As Boolean
    End Function
    <StructLayoutAttribute(LayoutKind.Sequential)>
    Public Structure SECURITY_DESCRIPTOR
        Public revision As Byte
        Public size As Byte
        Public control As Short
        Public owner As IntPtr
        Public group As IntPtr
        Public sacl As IntPtr
        Public dacl As IntPtr
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure SECURITY_ATTRIBUTES
        Public nLength As System.UInt32
        Public lpSecurityDescriptor As IntPtr
        Public bInheritHandle As Boolean
    End Structure
    Public Const SECURITY_DESCRIPTOR_REVISION As Integer = 1
    <DllImport("advapi32.dll", SetLastError:=True)>
    Public Function InitializeSecurityDescriptor(ByRef SecurityDescriptor As SECURITY_DESCRIPTOR, dwRevision As UInteger) As Boolean
    End Function
    <DllImport("advapi32.dll", SetLastError:=True)>
    Public Function SetSecurityDescriptorDacl(ByRef sd As SECURITY_DESCRIPTOR, ByVal daclPresent As Boolean, ByVal dacl As IntPtr, ByVal daclDefaulted As Boolean) As Boolean
    End Function
End Module
