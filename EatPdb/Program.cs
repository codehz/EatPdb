using CommandLine;
using PESupport;
using SharpPdb.Native;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace EatPdb {

    internal class Program {
        [Verb("rebuild", HelpText = "Rebuild PE file from PDB file (deprecated)")]
        public class DeprecatedOptions {

            [Value(0, HelpText = "Input File")]
            public string InputFile { get; set; }

            [Option("pdb", HelpText = "Pdb File")]
            public string PdbFile { get; set; }

            [Option('o', "out", Required = true, HelpText = "Output File")]
            public string OutputFile { get; set; }

            [Option("dll", HelpText = "DllName")]
            public string DllName { get; set; }

            [Option("def", HelpText = "Module-Definition file")]
            public string Definition { get; set; }

            [Option('v', "berbose", Default = false, HelpText = "Verbose Output")]
            public bool Verbose { get; set; }
        }

        [Verb("exec", HelpText = "Using config")]
        public class ConfigOptions {
            [Value(0)]
            public string ConfigFile { get; set; }
            [Option('d', "debug", Default = false, HelpText = "Debug mode")]
            public bool Debug { get; set; }
            [Option('v', "verbose", Default = false, HelpText = "Verbose Output")]
            public bool Verbose { get; set; }
        }

        private static void Main(string[] args) => Parser.Default.ParseArguments<DeprecatedOptions, ConfigOptions>(args)
                .WithParsed<ConfigOptions>(ConfigMain)
                .WithParsed<DeprecatedOptions>(DeprecatedMain);

        private static uint GetAlign(uint length, uint align = 512) => length % align == 0 ? length : (length / align + 1) * align;

        private static void ConfigMain(ConfigOptions options) {
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
                .WithTagMapping("!whitelist", typeof(Config.WhitelistFilter))
                .WithTagMapping("!blacklist", typeof(Config.BlacklistFilter))
                .WithTypeConverter(new Config.YamlTypeConverter())
                .Build();
            var cfg = deserializer.Deserialize<Config>(File.ReadAllText(options.ConfigFile));
            cfg.ApplyDefault();
            if (options.Debug)
                Console.WriteLine("{0}", ObjectDumper.Dump(cfg));
            RealMain(cfg, options.Verbose);
        }

        private static void DeprecatedMain(DeprecatedOptions options) {
            var filter = new Config.BlacklistFilter(new List<Config.IFilterData> {
                new Config.PrefixFilter("_"),
                new Config.PrefixFilter("?__"),
                new Config.PrefixFilter("??_"),
                new Config.PrefixFilter("??@"),
                new Config.PrefixFilter("?$TSS"),
                new Config.RegexFilter("std@@[QU]"),
            });
            var cfg = new Config {
                InputFile = options.InputFile,
                OutputFile = options.OutputFile,
                PdbFile = options.PdbFile,
                DefFile = options.Definition,
                DllName = options.DllName,
                Filter = filter
            };
            cfg.ApplyDefault();
            RealMain(cfg, options.Verbose);
        }

        private static void RealMain(Config config, bool verbose) {

            // Copy input file to output file, so we do not need to touch input file again
            File.Copy(config.InputFile, config.OutputFile, true);
            using var file = File.Open(config.OutputFile, FileMode.Open, FileAccess.ReadWrite);
            using var exp = File.CreateText(config.DefFile);
            using var action = new PEAction(file);
            using var pdb = new PdbFileReader(config.PdbFile);
            var symdb = new SymbolDatabase();
            Console.WriteLine("filtering ({0})", pdb.PublicSymbols.Length);

            // Collect all symbols
            foreach (var item in pdb.PublicSymbols.Where(item => config.Filter?.Filter(item.IsCode, item.Name) ?? true))
                symdb.Add((uint) item.RelativeVirtualAddress, item.Name);

            Console.WriteLine("symbols collected: {0}", symdb.Count());

            // Exclude imported symbols
            foreach (var sym in action.GetImportSymbols())
                if (symdb.RemoveName(sym) && verbose)
                    Console.WriteLine("Removed {0}", sym);

            Console.WriteLine("symbols filtered: {0}", symdb.Count());

            // Build cache
            var cache = symdb.ToArray();
            var sorted = symdb.Build();

            // Print exported symbols
            exp.Write("LIBRARY " + config.DllName + "\n");
            exp.Write("EXPORTS\n");
            foreach (var (name, idx) in sorted)
                exp.Write(string.Format("\t{0}\n", name));

            Console.WriteLine("starting rebuild PE file");

            // Calculate append length
            uint length = 0;
            var expdirlength = (uint)Marshal.SizeOf<ExportDir>();
            var dllnamelength = (uint)(config.DllName.Length + 1);
            var NumberOfFunctions = (uint) cache.Count();
            var functionslength = NumberOfFunctions * 4;
            var NumberOfNames = (uint) cache.Select(item => item.Value.Count).Aggregate(0, (a, b) => a + b);
            var ordinalslength = NumberOfNames * 2;
            var nameslength = NumberOfNames * 4;
            var stringslength = (uint) sorted.Select(kv => kv.Key.Length + 1).Aggregate(0, (a, b) => a + b);
            Console.WriteLine("NumberOfFunctions: {0}", NumberOfFunctions);
            Console.WriteLine("NumberOfNames: {0}", NumberOfNames);
            Console.WriteLine("Length Of ExportDir: {0}", expdirlength);
            Console.WriteLine("Length Of DllName: {0}", dllnamelength);
            Console.WriteLine("Length Of Functions: {0}", functionslength);
            Console.WriteLine("Length Of Ordinals: {0}", ordinalslength);
            Console.WriteLine("Length Of Names: {0}", nameslength);
            Console.WriteLine("Length Of Strings: {0}", stringslength);
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
            action.Writer.WriteByteString(config.DllName);
            foreach (var (key, _) in cache)
                action.Writer.WriteStruct(new RVA { Value = key });
            foreach (var (_, idx) in sorted)
                action.Writer.WriteStruct(new Ordinal { Value = idx });
            {
                var strscache = new List<uint>();
                var baseoff = (uint)file.Position;
                var baserva = VirtualEnd + expdirlength + dllnamelength + functionslength + ordinalslength;
                foreach (var (name, _) in sorted) {
                    strscache.Add((uint) file.Position - baseoff + baserva);
                    if (verbose)
                        Console.WriteLine("{0:X8} -> {1:X8}", file.Position, file.Position - baseoff + baserva);
                    action.Writer.WriteByteString(name);
                }

                foreach (var add in strscache)
                    action.Writer.WriteStruct(new RVA { Value = add });

                Console.WriteLine("VirtualEnd: {0} {0:X8}", VirtualEnd);
                Console.WriteLine("OriginalSize: {0} {0:X8}", OriginalSize);
                Console.WriteLine("RealAppend: {0} {0:X8}", file.Position - OriginalSize);
            }
        }
    }
}