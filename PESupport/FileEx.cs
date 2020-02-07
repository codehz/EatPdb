using System.IO;

namespace PESupport {
    public static class FileEx {
        public static void SeekRVA(this FileStream file, AddressResolver resolver, uint RVA) => file.Seek(resolver.Resolve(RVA), SeekOrigin.Begin);
    }
}
