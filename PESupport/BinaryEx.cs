using System.IO;
using System.Text;

namespace PESupport {

    public static class BinaryEx {

        public static string ReadByteString(this BinaryReader reader) {
            var builder = new StringBuilder();
            while (true) {
                var ch = reader.ReadByte();
                if (ch == 0)
                    break;
                builder.Append((char) ch);
            }
            return builder.ToString();
        }

        public static void WriteByteString(this BinaryWriter writer, string data) {
            var bytes = Encoding.ASCII.GetBytes(data);
            writer.Write(bytes);
            writer.Write((byte) 0);
        }

        public static T ReadStruct<T>(this BinaryReader reader) where T : unmanaged => StructOP<T>.Read(reader);

        public static void WriteStruct<T>(this BinaryWriter reader, T input) where T : unmanaged => StructOP<T>.Write(input, reader);
    }
}