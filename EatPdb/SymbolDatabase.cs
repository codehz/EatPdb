using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace EatPdb {
    internal class SymbolDatabase : IEnumerable<KeyValuePair<uint, SortedSet<string>>> {
        private readonly SortedDictionary<uint, SortedSet<string>> fullmap = new SortedDictionary<uint, SortedSet<string>>();
        private readonly Dictionary<string, uint> revmap = new Dictionary<string, uint>();
        public void Add(uint RVA, string name) {
            if (fullmap.TryGetValue(RVA, out var set))
                set.Add(name);
            else
                fullmap.Add(RVA, new SortedSet<string> { name });
            revmap.Add(name, RVA);
        }

        public void RemoveName(string name) {
            if (revmap.TryGetValue(name, out var RVA)) {
                fullmap.Remove(RVA);
                revmap.Remove(name);
            }
        }

        public IEnumerator<KeyValuePair<uint, SortedSet<string>>> GetEnumerator() => fullmap.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => fullmap.GetEnumerator();
    }
}
