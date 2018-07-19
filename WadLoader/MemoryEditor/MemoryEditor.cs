using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using CreatorSuite.Core.PE;

public enum FindGameResult
{
    GameNotFound,
    GameFound,
    OpenProcessIssue,
}

namespace LeagueClientAPI
{
    //Gutted Memory Editor from the Creator Suite
    internal sealed class MemoryEditor : IDisposable
    {
        #region Process Access Consts
        const int ProcessCreateThread = 0x0002;
        const int ProcessWmRead = 0x0010;
        const int ProcessVmWrite = 0x0020;
        const int ProcessQueryInformation = 0x0400;
        const int ProcessVmOperation = 0x0008;

        public enum Protection : uint
        {
            PageNoaccess = 0x01,
            PageReadonly = 0x02,
            PageReadwrite = 0x04,
            PageWritecopy = 0x08,
            PageExecute = 0x10,
            PageExecuteRead = 0x20,
            PageExecuteReadwrite = 0x40,
            PageExecuteWritecopy = 0x80,
            PageGuard = 0x100,
            PageNocache = 0x200,
        }

        [Flags]
        public enum MemoryAllocation : uint
        {
            MemCommit = 0x1000,
            MemReserve = 0x2000,
            MemDecommit = 0x4000,
            MemRelease = 0x8000,
            MemFree = 0x10000,
            MemPrivate = 0x20000,
            MemMapped = 0x40000,
            MemReset = 0x80000,
            MemTopDown = 0x100000,
            MemWriteWatch = 0x200000,
            MemPhysical = 0x400000,
            MemRotate = 0x800000,
            MemDifferentImageBaseOk = 0x800000,
            MemResetUndo = 0x1000000,
            MemLargePages = 0x20000000,
            Mem4MbPages = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Context
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FloatingSaveArea FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FloatingSaveArea
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;

            public uint Cr0NpxState;
        }

        [Flags]
        public enum ThreadAccess : int
        {
            Terminate = (0x0001),
            SuspendResume = (0x0002),
            GetContext = (0x0008),
            SetContext = (0x0010),
            SetInformation = (0x0020),
            QueryInformation = (0x0040),
            SetThreadToken = (0x0080),
            Impersonate = (0x0100),
            DirectImpersonation = (0x0200)
        }
        #endregion

        #region Imports
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(int hProcess,
          int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(int hProcess, int lpBaseAddress,
          byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool GetThreadContext(IntPtr hThread, ref Context lpContext);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, MemoryAllocation flAllocationType, Protection flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr lpAddress, IntPtr dwSize, MemoryAllocation freeType);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        public static extern bool SetThreadContext(IntPtr hThread, ref Context lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int ResumeThread(IntPtr hThread);
        #endregion

        #region Public & Private Vars
        private static readonly MemoryEditor _instance = new MemoryEditor();

        public IntPtr ProcessHandle
        {
            get { return _processHandle; }
        }

        private IntPtr _processHandle;
        public IntPtr BaseModule { get { return _baseModule; } }
        private IntPtr _baseModule;

        private int _moduleSize;
        public bool Unlocked { get; private set; }

        public static MemoryEditor Instance
        {
            get { return _instance; }
        }

        private EventHandler _processExitedHandler;
        public EventHandler ProcessExitedHandler
        {
            get { return _processExitedHandler; }
            set
            {
                if (_processExitedHandler == null)
                    _processExitedHandler = value;
            }
        }

        public void Unlock()
        {
            Unlocked = true;
        }

        #endregion

        #region Game Closed Callback

        private void ProcessExited(object sender, EventArgs e)
        {
            Unlocked = false;
            _processHandle = IntPtr.Zero;
            pGame = null;
            if (_processExitedHandler != null)
            {
                _processExitedHandler(sender, e);
            }
        }
        #endregion

        public void Suspend()
        {
            SuspendThread(_hThread);
        }

        public void Resume()
        {
            ResumeThread(_hThread);
        }

        public Context GetThreadContext()
        {
            Context context = new Context { ContextFlags = 0x10017 };
            GetThreadContext(_hThread, ref context);
            return context;
        }

        public void SetThreadContext(Context context)
        {
            SetThreadContext(_hThread, ref context);
        }

        #region FindGame
        private IntPtr _hThread;
        public Process pGame = null;
        public FindGameResult FindGame(string gameName, out String error, bool findUsingTitle = true, bool useContains = false)
        {

            error = "";
            if (findUsingTitle)
            {
                Process[] processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    //Sleep to stop Insane CPU Usage:
                    String titleName = process.MainWindowTitle;
                    Thread.Sleep(1);
                    if (String.CompareOrdinal(titleName, gameName) == 0 || (useContains && titleName.Contains(gameName)))
                    {
                        pGame = process;
                        break;
                    }
                }
            }
            else
            {
                Process[] processes = Process.GetProcessesByName(gameName);
                if (processes.Count() != 0)
                {
                    pGame = processes[0];
                }
            }

            if (pGame != null)
            {
                try
                {
                    _processHandle =
                        OpenProcess(ProcessQueryInformation | ProcessCreateThread | ProcessWmRead | ProcessVmOperation | ProcessVmWrite, false,
                            pGame.Id);

                    //TODO: double check this
                    if (pGame.ProcessName == "dwm")
                        return FindGameResult.GameNotFound;
                   
                    _hThread = OpenThread(ThreadAccess.SuspendResume | ThreadAccess.GetContext | ThreadAccess.SetContext, false, (uint)pGame.Threads[0].Id);
                    _baseModule = pGame.MainModule.BaseAddress;
                    _moduleSize = pGame.MainModule.ModuleMemorySize;

                    if ((uint)_baseModule == 0xdeadbabe)
                    {
                        PeHeaderReader reader = new PeHeaderReader(pGame.MainModule.FileName);
                        _baseModule = (IntPtr)((uint)pGame.MainModule.EntryPointAddress - reader.OptionalHeader32.AddressOfEntryPoint);
                        _moduleSize = (int)reader.OptionalHeader32.SizeOfImage;
                    }

                    pGame.EnableRaisingEvents = true;
                    pGame.Exited += ProcessExited;
                    return FindGameResult.GameFound;
                }
                catch (Exception e)
                {
                    error = FlattenException(e);
                    return FindGameResult.OpenProcessIssue;
                }
            }

            return FindGameResult.GameNotFound;
        }

        public static string FlattenException(Exception exception)
        {
            var stringBuilder = new StringBuilder();

            while (exception != null)
            {
                stringBuilder.AppendLine(exception.Message);
                stringBuilder.AppendLine(exception.StackTrace);

                exception = exception.InnerException;
            }

            return stringBuilder.ToString();
        }

        #endregion

        #region ReadMemory Funcs

        public bool ReadInt(IntPtr address, out Int32 val)
        {
            Byte[] buffer;
            bool result = ReadBytes(address, sizeof(Int32), out buffer);
            val = BitConverter.ToInt32(buffer, 0);
            return result;
        }

        public bool ReadBytes(IntPtr address, int size, out Byte[] buffer)
        {
            int bytesRead = 0;
            buffer = new byte[size];
            bool read = ReadProcessMemory((int)_processHandle, (int)address, buffer, buffer.Length, ref bytesRead);
            if (!read)
            {
                //TODO: Optimize and store the entire data if its available, would take 50mb RAM
                int datasize = 4096;
                byte[] pagefile = new byte[datasize];
                for (int i = 0; i < size; i += datasize)
                {
                    if (i + datasize > size)
                    {
                        datasize = size - i;
                        pagefile = new byte[datasize];
                    }

                    if (ReadProcessMemory((int)_processHandle, (int)address + i, pagefile, pagefile.Length, ref bytesRead))
                    {
                        read = true;
                        Buffer.BlockCopy(pagefile, 0, buffer, i, bytesRead);
                    }
                }
            }
            return read;
        }

        #endregion

        #region WriteMemory Funcs
        public bool WriteNullTerminatedString(IntPtr address, String Value)
        {
            Byte[] str = System.Text.Encoding.UTF8.GetBytes(Value);
            WriteBytes(address + str.Length, new byte[] {0x0});
            return WriteBytes(address, str);
        }

        public bool WriteBytes(IntPtr address, byte[] buffer)
        {
            int bytesWritten = 0;
            return WriteProcessMemory((int)_processHandle, (int)address, buffer, buffer.Length, ref bytesWritten);
        }

        #endregion

        #region Memory Allocation And Execution

        public IntPtr AllocateMemory(int size)
        {
            IntPtr allocatedAddress = VirtualAllocEx(_processHandle, IntPtr.Zero, size, MemoryAllocation.MemReserve | MemoryAllocation.MemCommit, Protection.PageExecuteReadwrite);
            return allocatedAddress;
        }

        public bool FreeMemory(IntPtr addr)
        {
            Boolean result = VirtualFree(addr, (IntPtr)0, MemoryAllocation.MemRelease);
            return result;
        }
        #endregion

        #region Pattern Scanning
        public bool FindPattern(string pattern, string mask, out uint val)
        {
            byte[] data;
            bool result = ReadBytes(_baseModule, _moduleSize, out data);
            byte[] patternBytes = GetBytesFromPattern(pattern);
            uint offset = Find(data, mask, patternBytes);
            if (offset == 0)
            {
                result = false;
                val = 0;
            }
            else
                val = (uint)_baseModule + offset;
            return result;
        }

        public bool FindPatternReverse(string pattern, string mask, IntPtr startAddress, out uint val)
        {
            if ((int)startAddress < (int)_baseModule)
                startAddress = _baseModule;

            byte[] data;
            bool result = ReadBytes(_baseModule, ((int)startAddress - (int)_baseModule), out data);
            byte[] patternBytes = GetBytesFromPattern(pattern);
            uint offset = FindReverse(data, mask, patternBytes);
            if (offset == 0)
            {
                result = false;
                val = 0;
            }
            else
                val = (uint)_baseModule + offset;
            return result;
        }

        public bool FindPattern(string pattern, string mask, IntPtr startAddress, out uint val)
        {
            if ((int)startAddress < (int)_baseModule)
                startAddress = _baseModule;

            byte[] data = new byte[_moduleSize - ((int)startAddress - (int)_baseModule)];
            //bool result = ReadBytes(startAddress, _moduleSize - ((int)startAddress - (int)_baseModule), out data);
            byte[] data2;
            bool result = ReadBytes(_baseModule, _moduleSize, out data2);
            Buffer.BlockCopy(data2, (int)startAddress - (int)_baseModule, data, 0, data.Length);
            byte[] patternBytes = GetBytesFromPattern(pattern);
            uint offset = Find(data, mask, patternBytes);
            if (offset == 0)
            {
                result = false;
                val = 0;
            }
            else
                val = (uint)startAddress + offset;
            return result;
        }

        private static byte[] GetBytesFromPattern(string pattern)
        {
            string[] split = pattern.Split(new[] { '\\', 'x' }, StringSplitOptions.RemoveEmptyEntries);
            var ret = new byte[split.Length];
            for (int i = 0; i < split.Length; i++)
            {
                ret[i] = byte.Parse(split[i], NumberStyles.HexNumber);
            }
            return ret;
        }

        private static uint Find(byte[] data, string mask, byte[] byteMask)
        {
            for (uint i = 0; i < data.Length; i++)
            {
                if (DataCompare(data, (int)i, byteMask, mask))
                    return i;
            }
            return 0;
        }

        private static uint FindReverse(byte[] data, string mask, byte[] byteMask)
        {
            for (uint i = (uint)(data.Length - mask.Length); i > 0; i--)
            {
                if (DataCompare(data, (int)i, byteMask, mask))
                    return i;
            }
            return 0;
        }

        private static bool DataCompare(byte[] data, int offset, byte[] byteMask, string mask)
        {
            for (int i = 0; i < mask.Length; i++)
            {
                if (mask[i] == 'x' && byteMask[i] != data[i + offset])
                {
                    return false;
                }
            }
            return true;
        }
        #endregion

        #region Dispose
        public void Dispose()
        {
        }
        #endregion
    }
}
