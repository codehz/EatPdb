using CommandLine;
using SharpPdb.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace PdbReader {

    internal class Program {

        public class Options {

            [Option('v', "Verbose", Default = false, HelpText = "Verbose output")]
            public bool Verbose { get; set; }

            [Option('d', "Demangle", Default = false, HelpText = "Demangle function name")]
            public bool Demangle { get; set; }

            [Option('i', "Input", Required = true, HelpText = "Input File")]
            public string InputFile { get; set; }
        }

        private static void Main(string[] args) => Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RealMain);

        private class SymbolEqualityComparer : IEqualityComparer<PdbPublicSymbol> {

            public bool Equals([AllowNull] PdbPublicSymbol x, [AllowNull] PdbPublicSymbol y) => x.RelativeVirtualAddress == y.RelativeVirtualAddress;

            public int GetHashCode([DisallowNull] PdbPublicSymbol obj) => obj.RelativeVirtualAddress.GetHashCode();
        }

        private static void RealMain(Options options) {
            try {
                using var reader = new PdbFileReader(options.InputFile);
                if (options.Verbose)
                    foreach (var item in from item in reader.PublicSymbols where !item.Name.StartsWith("_") orderby item.RelativeVirtualAddress select item)
                        Console.WriteLine("{0}:{1:X8} {2}", item.Segment, item.RelativeVirtualAddress, options.Demangle ? item.GetUndecoratedName() : item.Name);
                else {
                    var syms = from item in reader.PublicSymbols
                                where !item.Name.StartsWith("_")
                                select item;
                    Console.WriteLine("Symbol FullCount: {0}", syms.Count());
                    Console.WriteLine("Symbol DistinctCount: {0}", syms.Distinct(new SymbolEqualityComparer()).Count());

                    var functions = reader.Functions;
                    Console.WriteLine("Functions FullCount: {0}", functions.Count());
                }
            } catch (Exception e) {
                Console.WriteLine(e.ToString());
            }
        }
    }
}