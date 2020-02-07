using CommandLine;
using System;
using System.IO;
using PESupport;

namespace PEReader {
    class Program {
        public class Options {
            [Option('i', "Input", Required = true, HelpText = "Input File")]
            public string InputFile { get; set; }
        }
        static void Main(string[] args) => Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RealMain);
        private static readonly string[] DataDirName = new string[]{
            "Export",
            "Import",
            "Resource",
            "Exception",
            "Security",
            "BaseRelocationTable",
            "DebugDirectory",
            "CopyrightOrArchitectureSpecificData",
            "GlobalPtr",
            "TLSDirectory",
            "LoadConfigurationDirectory",
            "BoundImportDirectory",
            "ImportAddressTable",
            "DelayLoadImportDescriptors",
            "COMRuntimedescriptor",
            "Reserved",
        };
        private static void RealMain(Options options) {
            try {
                using var file = File.OpenRead(options.InputFile);
                using var reader = new BinaryReader(file);
                var header = reader.ReadStruct<DosHeader>();
                var ntheader_address = header.AddressOfNewExeHeader;
                file.Seek(ntheader_address, SeekOrigin.Begin);
                var ntheader = reader.ReadStruct<NtHeader>();
                if (ntheader.Signature != 0x4550) {
                    Console.WriteLine("Failed to parse nt header");
                    return;
                }
                if (ntheader.FileHeader.Machine != 0x8664) {
                    Console.WriteLine("Failed to parse nt header: only accept AMD64 architect: {0:X}", ntheader.FileHeader.Machine);
                    return;
                }
                if (ntheader.OptionalHeader.Magic != 0x20B) {
                    Console.WriteLine("Failed to parse nt optional header: only accept AMD64 architect: magic {0:X}", ntheader.OptionalHeader.Magic);
                    return;
                }
                var imagesize = ntheader.OptionalHeader.SizeOfImage;
                Console.WriteLine("Image Size: {0:X}", imagesize);
                var dirs = new DataDir[16];
                for (var i = 0; i < 16; i++) {
                    var dir = reader.ReadStruct<DataDir>();
                    Console.WriteLine("Data dir: {0:X8} {1:X8} ({2})", dir.VirtualAddress, dir.Size, DataDirName[i]);
                    dirs[i] = dir;
                }
                var resolver = new AddressResolver(ntheader.FileHeader.NumberOfSections);
                for (uint i = 0; i < ntheader.FileHeader.NumberOfSections; i++) {
                    var secheader = reader.ReadStruct<SectionHeader>();
                    Console.WriteLine("{0, 8}\n\t{1:X8}(Virtual Size)\n\t{2:X8}(Virtual Address)\n\t{3:X8}(Raw Data Size)\n\t{4:X8}(Raw Data Offset)\n\t{5:X8}(Diff)\n\tBITMAP: {6:X8}",
                        secheader.GetName(),
                        secheader.Misc.VirtualSize,
                        secheader.VirtualAddress,
                        secheader.SizeOfRawData,
                        secheader.PointerToRawData,
                        secheader.VirtualAddress - secheader.PointerToRawData,
                        secheader.Characteristics);
                    resolver.Put(secheader);
                }
                // Export table
                if (dirs[0].VirtualAddress != 0) {
                    file.SeekRVA(resolver, dirs[0].VirtualAddress);
                    var exp = reader.ReadStruct<ExportDir>();
                    file.SeekRVA(resolver, exp.Name);
                    Console.WriteLine("Dll Name: {0}", reader.ReadByteString());
                    file.SeekRVA(resolver, exp.AddressOfFunctions);
                    var addrs = new uint[exp.NumberOfFunctions];
                    for (uint i = 0; i < exp.NumberOfFunctions; i++)
                        addrs[i] = reader.ReadStruct<RVA>().Value;
                    file.SeekRVA(resolver, exp.AddressOfOrdinals);
                    var ords = new ushort[exp.NumberOfNames];
                    for (uint i = 0; i < exp.NumberOfNames; i++)
                        ords[i] = reader.ReadStruct<Ordinal>().Value;
                    var names = new string[exp.NumberOfNames];
                    for (uint i = 0; i < exp.NumberOfNames; i++) {
                        file.SeekRVA(resolver, exp.AddressOfNames + i * sizeof(uint));
                        file.SeekRVA(resolver, reader.ReadStruct<RVA>().Value);
                        names[i] = reader.ReadByteString();
                        Console.WriteLine("export: {2:X8} <- {1:X4}:{0}", names[i], ords[i], addrs[ords[i]]);
                    }
                }
                // Import table
                if (dirs[1].VirtualAddress != 0) {
                    var pos = resolver.Resolve(dirs[1].VirtualAddress);
                    for (uint i = 0; ; i++) {
                        file.Seek(pos, SeekOrigin.Begin);
                        var imp = reader.ReadStruct<ImportDir>();
                        pos = (uint) file.Position;
                        if (imp.Name == 0)
                            break;
                        file.SeekRVA(resolver, imp.Name);
                        Console.WriteLine("import from {0}", reader.ReadByteString());
                        var pos2 = resolver.Resolve(imp.FirstThunk);
                        for (uint j = 0; ; j++) {
                            file.Seek(pos2, SeekOrigin.Begin);
                            var thunk = reader.ReadStruct<ImportDirThunk>();
                            pos2 = (uint) file.Position;
                            if (thunk.IsEmpty())
                                break;
                            if (thunk.TryGetOrdinal(out var ord)) {
                                Console.WriteLine("#{0}", ord);
                            } else {
                                file.SeekRVA(resolver, (uint)thunk.Value);
                                var hint = reader.ReadStruct<ImportDirThunkHint>().Hint;
                                Console.WriteLine("\t{0:X4}:{1}", hint, reader.ReadByteString());
                            }
                        }
                    }
                }
            } catch (Exception e) {
                Console.WriteLine(e.ToString());
            }
        }
    }
}
