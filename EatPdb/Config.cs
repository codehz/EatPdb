using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace EatPdb {
#nullable enable
    public class Config {
        public interface IFilter {
            public bool Filter(bool isCode, string name);
        }
        public interface IFilterData : IFilter { }
        public class IsCodeFilter : IFilterData {
            public IsCodeFilter(bool isCode) => IsCode = isCode;

            public bool IsCode { get; set; }

            public bool Filter(bool isCode, string name) => isCode == IsCode;
        }
        public class FullNameFilter : IFilterData {
            public FullNameFilter(string name) => Name = name;

            public string Name { get; set; } = "";

            public bool Filter(bool isCode, string name) => name == Name;
        }
        public class PrefixFilter : IFilterData {
            public PrefixFilter(string prefix) => Prefix = prefix;

            public string Prefix { get; set; } = "";
            public bool Filter(bool isCode, string name) => name.StartsWith(Prefix);
        }
        public class RegexFilter : IFilterData {
            public RegexFilter(string pattern) => regex = new Regex(pattern, RegexOptions.Compiled);

            public Regex regex;
            public bool Filter(bool isCode, string name) => regex.IsMatch(name);
        }
        public class WhitelistFilter : IFilter {
            public WhitelistFilter(IEnumerable<IFilterData>? filters) => Filters = filters;

            public IEnumerable<IFilterData>? Filters { get; set; }
            public bool Filter(bool isCode, string name) => Filters == null ? false : Filters.Select(filter => filter.Filter(isCode, name)).Contains(true);
        }
        public class BlacklistFilter : IFilter {
            public BlacklistFilter(IEnumerable<IFilterData>? filters) => Filters = filters;

            public IEnumerable<IFilterData>? Filters { get; set; }
            public bool Filter(bool isCode, string name) => Filters == null ? true : !Filters.Select(filter => filter.Filter(isCode, name)).Contains(true);
        }
        public class YamlTypeConverter : IYamlTypeConverter {
            public bool Accepts(Type type) => type == typeof(WhitelistFilter) || type == typeof(BlacklistFilter);
            public object? ReadYaml(IParser parser, Type type) {
                var data = new List<IFilterData>();
                parser.Consume<SequenceStart>();
                while (!parser.TryConsume<SequenceEnd>(out var _)) {
                    if (parser.TryConsume<Scalar>(out var scalar)) {
                        data.Add(new FullNameFilter(scalar.Value));
                    } else if (parser.TryConsume<MappingStart>(out var _)) {
                        if (parser.TryConsume<Scalar>(out var key)) {
                            var value = parser.Consume<Scalar>();
                            switch (key.Value) {
                                case "is_code":
                                    data.Add(new IsCodeFilter(bool.Parse(value.Value)));
                                    break;
                                case "full":
                                case "name":
                                    data.Add(new FullNameFilter(value.Value));
                                    break;
                                case "prefix":
                                    data.Add(new PrefixFilter(value.Value));
                                    break;
                                case "regex":
                                case "pattern":
                                    data.Add(new RegexFilter(value.Value));
                                    break;
                                default:
                                    throw new NotImplementedException("Unknown key: " + value.Value);
                            }
                        }
                        parser.Consume<MappingEnd>();
                    } else {
                        throw new NotImplementedException("Unknown list");
                    }
                }
                if (type == typeof(WhitelistFilter)) {
                    return new WhitelistFilter(data);
                } else if (type == typeof(BlacklistFilter)) {
                    return new BlacklistFilter(data);
                }
                throw new NotImplementedException();
            }
            public void WriteYaml(IEmitter emitter, object? value, Type type) => throw new NotImplementedException();
        }
        [Required, YamlMember(Alias = "in")]
        public string InputFile { get; set; } = "";
        [Required, YamlMember(Alias = "out")]
        public string OutputFile { get; set; } = "";
        [YamlMember(Alias = "pdb")]
        public string PdbFile { get; set; } = "";
        [YamlMember(Alias = "def")]
        public string DefFile { get; set; } = "";
        [YamlMember(Alias = "dll_name")]
        public string DllName { get; set; } = "";
        [YamlMember(Alias = "filter")]
        public IFilter? Filter { get; set; }
        [YamlMember(Alias = "filterdb")]
        public string FilterOutDatabase { get; set; } = "";

        public void ApplyDefault() {
            if (PdbFile == "")
                PdbFile = Path.Join(Path.GetDirectoryName(InputFile), Path.GetFileNameWithoutExtension(InputFile) + ".pdb");
            if (DefFile == "")
                DefFile = Path.Join(Path.GetDirectoryName(OutputFile), Path.GetFileNameWithoutExtension(OutputFile) + ".def");
            if (DllName == "")
                DllName = Path.GetFileName(OutputFile);
        }
    }
#nullable restore
}
