using CommandLine;
using PESupport;
using SharpPdb.Native;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace EatPdb {
    class Program {
        public class Options {
            [Option('i', "Input", Required = true, HelpText = "Input File")]
            public string InputFile { get; set; }
            [Option('p', "Pdb", Required = true, HelpText = "Pdb File")]
            public string PdbFile { get; set; }
            [Option('o', "Ouput", Required = true, HelpText = "Output File")]
            public string OuputFile { get; set; }
            [Option("DllName", Required = true, HelpText = "DllName")]
            public string DllName { get; set; }
        }
        static void Main(string[] args) => Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RealMain);

        private static uint GetAlign(uint length, uint align = 512) => length % align == 0 ? length : (length / align + 1) * align;
        private static void RealMain(Options options) {
            try {
                // Copy input file to output file, so we do not need to touch input file again
                File.Copy(options.InputFile, options.OuputFile, true);
                using var file = File.Open(options.OuputFile, FileMode.Open, FileAccess.ReadWrite);
                using var action = new PEAction(file);
                using var pdb = new PdbFileReader(options.PdbFile);
                var symdb = new SymbolDatabase();

                // Collect all symbols
                foreach (var item in pdb.PublicSymbols.Where(item => item.IsCode))
                    symdb.Add((uint) item.RelativeVirtualAddress, item.Name);

                // Exclude imported symbols
                foreach (var sym in action.GetImportSymbols())
                    symdb.RemoveName(sym);

                // Calculate append length
                uint length = 0;
                var cache = symdb.ToArray();
                var expdirlength = (uint)Marshal.SizeOf<ExportDir>();
                var dllnamelength = (uint)(options.DllName.Length + 1);
                var NumberOfFunctions = (uint) cache.Count();
                var functionslength = NumberOfFunctions * 4;
                var NumberOfNames = (uint) cache.Select(item => item.Value.Count).Aggregate(0, (a, b) => a + b);
                var ordinalslength = NumberOfNames * 2;
                var nameslength = NumberOfNames * 4;
                var stringslength = (uint)cache.Select(item => item.Value.Select(name => name.Length + 1).Aggregate(0, (a, b) => a + b)).Aggregate(0, (a, b) => a + b);
                Console.WriteLine("ExportDir: {0}", expdirlength);
                Console.WriteLine("DllName: {0}", dllnamelength);
                Console.WriteLine("Functions: {0}", functionslength);
                Console.WriteLine("Ordinals: {0}", ordinalslength);
                Console.WriteLine("Names: {0}", nameslength);
                Console.WriteLine("Strings: {0}", stringslength);
                length = expdirlength + dllnamelength + functionslength + ordinalslength + nameslength + stringslength;
                Console.WriteLine("Addition length: {0}", length);

                // Start modify header
                var VirtualEnd = action.GetEnding();
                var OriginalSize = (uint)file.Length;
                action.PatchNtHeader(GetAlign(length));
                action.PatchDir(0, VirtualEnd, length);
                {
                    var header = new SectionHeader {};
                    header.SetName(".hacked");
                    header.Misc.VirtualSize = length;
                    header.VirtualAddress = VirtualEnd;
                    header.SizeOfRawData = GetAlign(length);
                    header.PointerToRawData = OriginalSize;
                    header.Characteristics = 0x40000040;
                    action.AppendSection(header);
                }

                // Write export table
                file.SetLength(OriginalSize + GetAlign(length));
                {
                    var expdir = new ExportDir {};
                    expdir.Name = VirtualEnd + expdirlength;
                    expdir.Base = 1;
                    expdir.NumberOfFunctions = NumberOfFunctions;
                    expdir.NumberOfNames = NumberOfNames;
                    expdir.AddressOfFunctions = VirtualEnd + expdirlength + dllnamelength;
                    expdir.AddressOfOrdinals = VirtualEnd + expdirlength + dllnamelength + functionslength;
                    expdir.AddressOfNames = VirtualEnd + expdirlength + dllnamelength + functionslength + ordinalslength + stringslength;
                    action.WriteExport(expdir);
                }
                action.Writer.WriteByteString(options.DllName);
                foreach (var (key, _) in cache)
                    action.Writer.WriteStruct(new RVA { Value = key });
                {
                    ushort idx = 0;
                    foreach (var (_, set) in cache) {
                        foreach (var _ in set) {
                            action.Writer.WriteStruct(new Ordinal { Value = idx });
                        }
                        idx++;
                    }
                }
                {
                    var strscache = new List<uint>();
                    var basepos = (uint)file.Position;
                    var baseoff = VirtualEnd + expdirlength + dllnamelength + functionslength + ordinalslength;
                    foreach (var (_, set) in cache)
                        foreach (var name in set) {
                            strscache.Add((uint) file.Position - basepos + baseoff);
                            action.Writer.WriteByteString(name);
                        }

                    foreach (var add in strscache)
                        action.Writer.WriteStruct(new RVA { Value = add });
                }
            } catch (Exception e) {
                Console.Error.WriteLine(e);
            }
        }
    }
}
