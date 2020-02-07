using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PESupport {

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct DosHeader {
        public fixed byte MZSignature[2];
        public ushort UsedBytesInTheLastPage;
        public ushort FileSizeInPages;
        public ushort NumberOfRelocationItems;
        public ushort HeaderSizeInParagraphs;
        public ushort MinimumExtraParagraphs;
        public ushort MaximumExtraParagraphs;
        public ushort InitialRelativeSS;
        public ushort InitialSP;
        public ushort Checksum;
        public ushort InitialIP;
        public ushort InitialRelativeCS;
        public ushort AddressOfRelocationTable;
        public ushort OverlayNumber;
        public fixed ushort Reserved[4];
        public ushort OEMid;
        public ushort OEMinfo;
        public fixed ushort Reserved2[10];
        public uint AddressOfNewExeHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NtHeader {
        public uint Signature;
        public FileHeader FileHeader;
        public OptionalHeader OptionalHeader;

        public bool CheckHealth() => Signature == 0x4550 && FileHeader.Machine == 0x8664 && OptionalHeader.Magic == 0x20B;
        public void AssertHealth() {
            if (!CheckHealth())
                throw new NotSupportedException("x86_64 PE file expected");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileHeader {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeaders;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OptionalHeader {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAligment;
        public uint FileAligment;
        public ushort MajorOperationSystemVersion;
        public ushort MinorOperationSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DataDir {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SectionHeader {
        public fixed byte Name[8];
        public SectionHeaderMisc Misc;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;

        public unsafe string GetName() {
            fixed (byte* name = Name) {
                return Marshal.PtrToStringAnsi((IntPtr) name, 8);
            }
        }

        public unsafe void SetName(string name) {
            var len = name.Length;
            if (len >= 8)
                throw new IndexOutOfRangeException();
            var data = Encoding.ASCII.GetBytes(name);
            for (uint i = 0; i < 8; i++) {
                if (i < len) {
                    Name[i] = data[i];
                } else {
                    Name[i] = 0;
                }
            }
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct SectionHeaderMisc {
        [FieldOffset(0)]
        public uint PhysicalAddress;
        [FieldOffset(0)]
        public uint VirtualSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ExportDir {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name; // RVA
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions; // RVA
        public uint AddressOfNames; // RVA
        public uint AddressOfOrdinals; // RVA
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Ordinal {
        public ushort Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RVA {
        public uint Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImportDir {
        public uint OriginalFirstThunk; // RVA
        public uint TimeDateStamp;
        public uint ForwardChain;
        public uint Name; // RVA
        public uint FirstThunk; // RVA
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImportDirThunk {
        public ulong Value;

        public bool IsEmpty() => Value == 0;
        public bool TryGetOrdinal(out uint ordinal) {
            if ((Value & 0x8000000000000000) != 0) {
                ordinal = (uint) Value;
                return true;
            }
            ordinal = 0;
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImportDirThunkHint {
        public ushort Hint;
    }
}
