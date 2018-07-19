using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net.Sockets;
using System.Threading;
using AsmResolver;
using AsmResolver.X86;
using LeagueClientAPI;

namespace CustomSkinLoader
{
    public static class WadLoader
    {
        private static readonly List<String> WadFiles = new List<String>();
        private static readonly Thread FindGameThread = new Thread(FindGame){ IsBackground = true };
        private static readonly MemoryEditor MemoryEditor = MemoryEditor.Instance;
        internal enum State
        {
            FindGame,
            LoadWads,
            WaitForNewGame
        }

        internal static State ThreadState = State.FindGame;

        static WadLoader()
        {
            //Only is called after AddWadFile is called
            MemoryEditor.ProcessExitedHandler += SearchForNewGame;
            //Start Thread to Scan for Game:
            if (!FindGameThread.IsAlive)
                FindGameThread.Start();
        }

        private static void SearchForNewGame(object sender, EventArgs e)
        {
            ThreadState = State.FindGame;
        }

        private static void FindGame()
        {
            while (true)
            {
                switch (ThreadState)
                {
                    case State.FindGame:
                        string error;
                        FindGameResult result = MemoryEditor.FindGame("League of Legends (TM) Client", out error);
                        //MemoryEditor.Context context = MemoryEditor.GetThreadContext();
                        if (result == FindGameResult.GameFound)
                            ThreadState = State.LoadWads;
                        break;
                    case State.LoadWads:
                        uint addr;
                        if (MemoryEditor.FindPattern(@"\xE8\x00\x00\x00\x00\x8B\x4C\x24\x2C\x8A\xD8\x85\xC9",
                            "x????xxxxxxxx", out addr))
                        {
                            uint thisFunc;
                            MemoryEditor.FindPatternReverse(@"\x81\xEC\x3C\x01\x00\x00\xA1", "xxxxxxx", (IntPtr) addr, out thisFunc);
                            uint ECDSA;
                            MemoryEditor.FindPattern(@"\xE8\x00\x00\x00\x00\x84\xC0\x75\x34\x8D\x84\x24\x00\x00\x00\x00", @"x????xxxxxxx????",
                                out ECDSA);
                            int offset;
                            MemoryEditor.ReadInt((IntPtr)ECDSA + 1, out offset);
                            ECDSA = (uint)(ECDSA + offset + 5);
                            int callOffset = (int)addr - (int)thisFunc;
                            MemoryEditor.ReadInt((IntPtr)addr + 1, out offset);
                            addr = (uint)(addr + offset + 5);
                            LoadWadFiles((IntPtr)thisFunc, callOffset, (IntPtr)addr, (IntPtr)ECDSA);
                            ThreadState = State.WaitForNewGame;
                        }
                        break;
                }
                Thread.Sleep(1);
            }
        }

        /*
            Byte[] asm = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x00, 0xA1, 0xC0, 0x00, 0x00, 0x00 };
            X86Disassembler d = new X86Disassembler(new MemoryStreamReader(asm));
            X86Instruction i = d.ReadNextInstruction();
            i = d.ReadNextInstruction();
            i = d.ReadNextInstruction();
         */

        private static void LoadWadFiles(IntPtr function1Address, int funcOffset, IntPtr functionAddress, IntPtr ECDSA)
        {
            uint functionLength;
            uint functionLength1;
            uint ECDSALen;
            MemoryEditor.FindPattern(@"\xC2\x04\x00\xCC", "xxxx", ECDSA, out ECDSALen);
            MemoryEditor.FindPattern(@"\xC2\x08\x00\xCC", "xxxx", functionAddress, out functionLength);
            MemoryEditor.FindPattern(@"\xC3\x57\xE8\x00\x00\x00\x00\xCC", "xxx????x", function1Address, out functionLength1);
            functionLength = (functionLength - (uint)functionAddress) + 4;
            ECDSALen = (ECDSALen - (uint)ECDSA) + 4;
            functionLength1 = (functionLength1 - (uint)function1Address) + 8;
            //Steal the function:
            Byte[] asmECDSA;
            MemoryEditor.ReadBytes(ECDSA, (int)ECDSALen, out asmECDSA);
            Byte[] asm1;
            MemoryEditor.ReadBytes(function1Address, (int)functionLength1, out asm1);
            Byte[] asm;
            MemoryEditor.ReadBytes(functionAddress, (int)functionLength, out asm);
            //Allocate and copy the function to our new memory
            IntPtr AllocatedMemory = MemoryEditor.AllocateMemory(0x1000);
            //MemoryEditor.WriteBytes(AllocatedMemory, asm);
            //Fix the bytecode for the new offsets:
            X86Disassembler disassembler = new X86Disassembler(new MemoryStreamReader(asmECDSA));
            while (disassembler.BaseStream.Position != disassembler.BaseStream.Length)
            {
                X86Instruction instruction = disassembler.ReadNextInstruction();
                if (instruction.Mnemonic == X86Mnemonic.Je && instruction.Offset == 0x49)
                {
                    Buffer.BlockCopy(new Byte[] { 0x90, 0x90 }, 0, asmECDSA, (int)instruction.Offset, 2);
                    continue;
                }
                if (instruction.Mnemonic != X86Mnemonic.Call || (instruction.Operand1 != null && instruction.Operand1.OperandUsage == X86OperandUsage.DwordPointer))
                    continue;

                if (instruction.Operand1.Value.ToString() == "Eax")
                    continue;
                //Fix the Call:
                int offset;
                MemoryEditor.ReadInt(ECDSA + (int)instruction.Offset + 1, out offset);
                int callAddress = (5 + (int)instruction.Offset + (int)ECDSA) + offset;
                offset = callAddress - ((int)AllocatedMemory + (int)instruction.Offset + 5);
                Buffer.BlockCopy(BitConverter.GetBytes(offset), 0, asmECDSA, (int)instruction.Offset + 1, 4);
            }

            MemoryEditor.WriteBytes(AllocatedMemory, asmECDSA);
            AllocatedMemory += asmECDSA.Length;

            disassembler = new X86Disassembler(new MemoryStreamReader(asm));
            while (disassembler.BaseStream.Position != disassembler.BaseStream.Length)
            {
                X86Instruction instruction = disassembler.ReadNextInstruction();

                /*if (instruction.Mnemonic == X86Mnemonic.Jne)
                {
                    Buffer.BlockCopy(new Byte[] { 0xEB }, 0, asm, (int)instruction.Offset, 1);
                    continue;
                }*/

                if (instruction.Mnemonic != X86Mnemonic.Call || (instruction.Operand1 != null && instruction.Operand1.OperandUsage == X86OperandUsage.DwordPointer))
                    continue;

                if (instruction.Offset == 0x128)
                {
                    Buffer.BlockCopy(BitConverter.GetBytes(((int)AllocatedMemory - asmECDSA.Length) - ((int)AllocatedMemory + (int)instruction.Offset + 5))
                        , 0, asm, (int)instruction.Offset + 1, 4);
                    continue;
                }
                //Fix the Call:
                int offset;
                MemoryEditor.ReadInt(functionAddress + (int)instruction.Offset + 1, out offset);
                int callAddress = (5 + (int) instruction.Offset + (int) functionAddress) + offset;
                offset = callAddress - ((int)AllocatedMemory + (int) instruction.Offset + 5);
                Buffer.BlockCopy(BitConverter.GetBytes(offset), 0, asm, (int)instruction.Offset + 1, 4);
            }

            MemoryEditor.WriteBytes(AllocatedMemory, asm);
            AllocatedMemory += asm.Length;

            disassembler = new X86Disassembler(new MemoryStreamReader(asm1));
            while (disassembler.BaseStream.Position != disassembler.BaseStream.Length)
            {
                X86Instruction instruction = disassembler.ReadNextInstruction();

                if (instruction.Mnemonic != X86Mnemonic.Call || (instruction.Operand1 != null && instruction.Operand1.OperandUsage == X86OperandUsage.DwordPointer))
                    continue;

                if (instruction.Offset == funcOffset)
                {
                    Buffer.BlockCopy(BitConverter.GetBytes(((int)AllocatedMemory - asm.Length) - ((int)AllocatedMemory + (int)instruction.Offset + 5))
                        , 0, asm1, (int)instruction.Offset + 1, 4);
                    continue;
                }

                //Fix the Call:
                int offset;
                MemoryEditor.ReadInt(function1Address + (int)instruction.Offset + 1, out offset);
                int callAddress = (5 + (int)instruction.Offset + (int)function1Address) + offset;
                offset = callAddress - ((int)AllocatedMemory + (int)instruction.Offset + 5);
                Buffer.BlockCopy(BitConverter.GetBytes(offset), 0, asm1, (int)instruction.Offset + 1, 4);
            }
            MemoryEditor.WriteBytes(AllocatedMemory, asm1);
            IntPtr LoadWadFunction = AllocatedMemory;
            AllocatedMemory += asm1.Length;
            //Allocate Variables
            IntPtr StringAddress = AllocatedMemory + 0x10;

            //0x38 for failedFunctionCallback    
            AllocatedMemory = StringAddress + 0x110;
            byte[] customAsm =
            {
                0x60, //pushad
                0x6A, 0x00,
                0x68, 0x00, 0x00, 0x00, 0x00,
                0xE8, 0x00, 0x00, 0x00, 0x00,
                0x5B, //pop x2,
                0x5B,
                0x61, //popad
                0xEB, 0xFE //Endless Loop so we know to correct the EIP
            };
            Buffer.BlockCopy(BitConverter.GetBytes((uint)StringAddress), 0, customAsm, 0x4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)LoadWadFunction - ((uint)AllocatedMemory + 0xD)), 0, customAsm, 0x9, 4);
            MemoryEditor.WriteBytes(AllocatedMemory, customAsm);

            int lockedEip = (int)AllocatedMemory + customAsm.Length - 2;
            MemoryEditor.Suspend();
            MemoryEditor.Context context = MemoryEditor.GetThreadContext();
            uint originalEip = context.Eip;
            //Load Each WADFile:
            foreach (String wadFile in WadFiles)
            {
                MemoryEditor.Suspend();
                context.Eip = (uint)AllocatedMemory;
                MemoryEditor.SetThreadContext(context);
                MemoryEditor.WriteNullTerminatedString(StringAddress, wadFile);
                MemoryEditor.Resume();
                //NOTE: THE CODE HAS TO RUN ON MAIN THREAD TO PROPERLY LOAD WADS
                //MemoryEditor.WaitForSingleObject(MemoryEditor.CreateRemoteThread(AllocatedMemory, IntPtr.Zero));
                bool loop = true;
                while (loop)
                {
                    context = MemoryEditor.GetThreadContext();
                    loop = context.Eip != lockedEip;
                    MemoryEditor.Resume();
                }
            }
            context.Eip = originalEip;
            MemoryEditor.SetThreadContext(context);
            MemoryEditor.FreeMemory(AllocatedMemory);
        }

        public static bool AddWadFile(String wadFile)
        {
            if (WadFiles.Contains(wadFile))
                return false;

            WadFiles.Add(wadFile);
            return true;
        }
    }
}
