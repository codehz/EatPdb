using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace EatPdb {

    internal class SymbolDatabase : IEnumerable<KeyValuePair<uint, SortedSet<string>>> {
        private readonly SortedDictionary<uint, SortedSet<string>> fullmap = new SortedDictionary<uint, SortedSet<string>>();
        private readonly SortedDictionary<string, uint> revmap = new SortedDictionary<string, uint>();

        public void Add(uint RVA, string name) {
            if (fullmap.TryGetValue(RVA, out var set))
                set.Add(name);
            else
                fullmap.Add(RVA, new SortedSet<string> { name });
            revmap.Add(name, RVA);
        }

        public bool RemoveName(string name) {
            if (revmap.TryGetValue(name, out var RVA)) {
                fullmap.Remove(RVA);
                revmap.Remove(name);
                return true;
            }
            return false;
        }

        public IEnumerator<KeyValuePair<uint, SortedSet<string>>> GetEnumerator() => fullmap.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => fullmap.GetEnumerator();

        public KeyValuePair<string, ushort>[] Build() {
            var tempid = new Dictionary<uint, ushort>();
            ushort idx = 0;
            foreach (var (key, _) in fullmap)
                tempid.Add(key, idx++);
            var ret = new SortedDictionary<string, ushort>();
            foreach (var (name, rva) in revmap) {
                if (tempid.TryGetValue(rva, out var id)) {
                    ret.Add(name, id);
                } else {
                    throw new IndexOutOfRangeException();
                }
            }
            return ret.ToArray();
        }
    }
}