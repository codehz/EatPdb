using System.IO;
using System.Runtime.InteropServices;

namespace PESupport {

    internal static class StructOP<T> where T : unmanaged {
        private static readonly int Size = Marshal.SizeOf<T>();

        public static unsafe T Read(BinaryReader reader) {
            T val;
            var ptr = (byte*) &val;
            for (uint i = 0; i < Size; i++)
                *ptr++ = reader.ReadByte();
            return val;
        }

        public static unsafe void Write(T input, BinaryWriter writer) {
            var ptr = (byte*) &input;
            for (uint i = 0; i < Size; i++)
                writer.Write(*ptr++);
        }
    }
}