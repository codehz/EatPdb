using System;
using System.Collections.Generic;

namespace PESupport {
    public class AddressResolver {
        private readonly List<SectionHeader> Sections;

        [Serializable]
        private class AddressNotFoundException : Exception {
            public AddressNotFoundException(uint RVA) : base(string.Format("RVA {0} not mapped in this PE file", RVA)) { }
        }

        public AddressResolver(uint number) => Sections = new List<SectionHeader>();
        public void Put(SectionHeader header) => Sections.Add(header);
        public uint Resolve(uint RVA) {
            foreach (var secheader in Sections) {
                if (secheader.VirtualAddress <= RVA && secheader.VirtualAddress + secheader.Misc.VirtualSize > RVA) {
                    return RVA - secheader.VirtualAddress + secheader.PointerToRawData;
                }
            }
            throw new AddressNotFoundException(RVA);
        }
    }
}
