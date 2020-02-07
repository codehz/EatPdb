using PESupport;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace EatPdb {
    internal class PEAction : IDisposable {
        private readonly FileStream File;
        private readonly DataDir[] Dirs;
        public readonly BinaryReader Reader;
        public readonly BinaryWriter Writer;
        public readonly AddressResolver Resolver;
        private readonly uint NTHeaderOffset;
        private NtHeader NtHeader;

        internal PEAction(FileStream file) {
            File = file;
            Reader = new BinaryReader(file);
            Writer = new BinaryWriter(file);

            NTHeaderOffset = Reader.ReadStruct<DosHeader>().AddressOfNewExeHeader;
            File.Seek(NTHeaderOffset, SeekOrigin.Begin);
            NtHeader = Reader.ReadStruct<NtHeader>();
            NtHeader.AssertHealth();
            Dirs = new DataDir[16];
            for (var i = 0; i < 16; i++)
                Dirs[i] = Reader.ReadStruct<DataDir>();
            Resolver = new AddressResolver(NtHeader.FileHeader.NumberOfSections);
            for (uint i = 0; i < NtHeader.FileHeader.NumberOfSections; i++)
                Resolver.Put(Reader.ReadStruct<SectionHeader>());
        }

        internal uint GetEnding() => NtHeader.OptionalHeader.SizeOfImage;

        internal void PatchNtHeader(uint addition) => NtHeader.OptionalHeader.SizeOfImage += addition;

        internal void PatchDir(uint index, uint address, uint length) {
            Dirs[index].VirtualAddress = address;
            Dirs[index].Size = length;
            File.Seek(NTHeaderOffset + Marshal.SizeOf<NtHeader>() + index * Marshal.SizeOf<DataDir>(), SeekOrigin.Begin);
            Writer.WriteStruct(Dirs[index]);
        }

        internal void AppendSection(SectionHeader header) {
            var lastSec = NtHeader.FileHeader.NumberOfSections;
            NtHeader.FileHeader.NumberOfSections += 1;
            File.Seek(NTHeaderOffset, SeekOrigin.Begin);
            Writer.WriteStruct(NtHeader);
            File.Seek(16 * Marshal.SizeOf<DataDir>() + lastSec * Marshal.SizeOf<SectionHeader>(), SeekOrigin.Current);
            Writer.WriteStruct(header);
            Resolver.Put(header);
        }

        internal void Seek(uint RVA) => File.SeekRVA(Resolver, RVA);

        internal void WriteExport(ExportDir expdir) {
            Seek(Dirs[0].VirtualAddress);
            Writer.WriteStruct(expdir);
        }

        internal IEnumerable<string> GetImportSymbols() {
            if (Dirs[1].VirtualAddress != 0) {
                var pos = Resolver.Resolve(Dirs[1].VirtualAddress);
                for (uint i = 0; ; i++) {
                    File.Seek(pos, SeekOrigin.Begin);
                    var imp = Reader.ReadStruct<ImportDir>();
                    pos = (uint) File.Position;
                    if (imp.Name == 0)
                        break;
                    var pos2 = Resolver.Resolve(imp.FirstThunk);
                    for (uint j = 0; ; j++) {
                        File.Seek(pos2, SeekOrigin.Begin);
                        var thunk = Reader.ReadStruct<ImportDirThunk>();
                        pos2 = (uint) File.Position;
                        if (thunk.IsEmpty())
                            break;
                        if (thunk.TryGetOrdinal(out var ord)) {
                        } else {
                            File.SeekRVA(Resolver, (uint) thunk.Value);
                            Reader.ReadStruct<ImportDirThunkHint>();
                            yield return Reader.ReadByteString();
                        }
                    }
                }
            }
        }

        public void Dispose() => Reader.Dispose();
    }
}
