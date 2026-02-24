using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WinFormsApp1
{
    public sealed class DexManipulator
    {
        public sealed class PipelineResult
        {
            public SummaryInfo Summary { get; set; } = new SummaryInfo();
            public Dictionary<string, byte[]> DexBuffers { get; set; } = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            public Dictionary<string, string> JsonBuffers { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public sealed class SummaryInfo
        {
            public List<string> ExtractedFiles { get; set; } = new();
            public List<string> DexFiles { get; set; } = new();
            public List<string> JsonFiles { get; set; } = new();
            public List<RestoredInfo> Restored { get; set; } = new();
            public double ElapsedSeconds { get; set; }
            public MultiDexHeader MultiDex { get; set; } = new();
            public List<string> Notes { get; set; } = new();
        }

        public sealed class RestoredInfo
        {
            public int DexIndex { get; set; }
            public string DexFile { get; set; } = "";
            public int RestoredMethods { get; set; }
        }

        public sealed class MultiDexHeader
        {
            public ushort Version { get; set; }
            public ushort DexCount { get; set; }
        }

        public sealed class MultiDexCode
        {
            public ushort Version { get; set; }
            public ushort DexCount { get; set; }
            public uint[] DexOffsets { get; set; } = Array.Empty<uint>();
            public List<DexCode> DexCodes { get; set; } = new();
            public List<string> Warnings { get; set; } = new();
        }

        public sealed class DexCode
        {
            public ushort MethodCount { get; set; }
            public List<InstructionEntry> Instructions { get; set; } = new();
        }

        public sealed class InstructionEntry
        {
            public uint MethodIndex { get; set; }
            public uint Size { get; set; }
            public byte[] Data { get; set; } = Array.Empty<byte>();
        }

        // DEX parsing models
        private sealed class DexHeader
        {
            public uint FileSize;
            public uint StringIdsSize, StringIdsOff;
            public uint TypeIdsSize, TypeIdsOff;
            public uint ProtoIdsSize, ProtoIdsOff;
            public uint MethodIdsSize, MethodIdsOff;
            public uint ClassDefsSize, ClassDefsOff;
        }

        private sealed class DexMethodId
        {
            public int MethodIdx;
            public ushort ClassIdx;
            public ushort ProtoIdx;
            public uint NameIdx;
            public string ClassDescriptor = "";
            public string Name = "";
        }

        private sealed class DexMethodInfo
        {
            public int MethodIdx;
            public string ClassDescriptor = "";
            public string Name = "";
            public string ProtoShorty = "";
            public string ReturnType = "";
            public List<string> ParamTypes = new();
            public uint? CodeOff;
            public uint? InsnsOff;
        }

        private sealed class DexParseResult
        {
            public DexHeader Header = new DexHeader();
            public List<string> Strings = new();
            public List<string> Types = new();
            public List<DexMethodInfo> Methods = new();
            public Dictionary<int, uint> CodeOffByMethodIdx = new();
        }

        public PipelineResult RunFullPipeline(byte[] dexInput, byte[] codeInput)
        {
            var start = DateTime.UtcNow;
            var notes = new List<string>();

            byte[] zipBuf = ExtractEmbeddedZipFromDex(dexInput);
            using var zipMs = new MemoryStream(zipBuf, writable: false);
            using var zip = new ZipArchive(zipMs, ZipArchiveMode.Read, leaveOpen: false);

            var extractedFiles = zip.Entries
                .Where(e => !string.IsNullOrEmpty(e.FullName) && !e.FullName.EndsWith("/", StringComparison.Ordinal))
                .Select(e => e.FullName)
                .ToList();

            // Find dex entries
            var dexEntries = zip.Entries
                .Where(e => IsClassesDex(e.FullName))
                .Select(e => e.FullName)
                .ToList();

            dexEntries.Sort(NaturalDexSort);

            if (dexEntries.Count == 0)
            {
                notes.Add("No classes*.dex found; falling back to any .dex entries");
                dexEntries = zip.Entries
                    .Where(e => e.FullName.EndsWith(".dex", StringComparison.OrdinalIgnoreCase))
                    .Select(e => e.FullName)
                    .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            // Read dex buffers from zip
            var dexBuffers = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in dexEntries)
            {
                var entry = zip.GetEntry(name);
                if (entry == null) continue;
                using var es = entry.Open();
                using var ms = new MemoryStream();
                es.CopyTo(ms);
                dexBuffers[name] = ms.ToArray();
            }

            var multi = ReadMultiDexCode(codeInput);

            if (dexEntries.Count > multi.DexCount)
                notes.Add($"Embedded ZIP has {dexEntries.Count} dex files, but code.bin dexCount is {multi.DexCount}. Only first {multi.DexCount} dex will be patched.");
            else if (dexEntries.Count < multi.DexCount)
                notes.Add($"code.bin dexCount is {multi.DexCount}, but embedded ZIP has only {dexEntries.Count} dex files. Only {dexEntries.Count} dex will be patched.");

            var jsonFiles = new List<string>();
            var jsonBuffers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var restored = new List<RestoredInfo>();

            int patchCount = (int)Math.Min(multi.DexCount, (ushort)dexEntries.Count);

            for (int dexIdx = 0; dexIdx < patchCount; dexIdx++)
            {
                string dexName = dexEntries[dexIdx];
                if (!dexBuffers.TryGetValue(dexName, out var dexBuf) || dexBuf.Length == 0)
                    continue;

                var parsed = ParseDex(dexBuf);

                // map methodIdx -> insnsOff
                var byMethodInsns = new Dictionary<uint, uint>();
                foreach (var m in parsed.Methods)
                {
                    if (m.InsnsOff.HasValue)
                        byMethodInsns[(uint)m.MethodIdx] = m.InsnsOff.Value;
                }

                // methodIdx -> class name
                var methodMeta = new Dictionary<uint, string>();
                foreach (var m in parsed.Methods)
                {
                    methodMeta[(uint)m.MethodIdx] = ClassNameFromDescriptor(m.ClassDescriptor);
                }

                var classGroups = new Dictionary<string, List<Dictionary<string, object>>>(StringComparer.Ordinal);
                int restoredMethods = 0;

                foreach (var insn in multi.DexCodes[dexIdx].Instructions)
                {
                    if (!byMethodInsns.TryGetValue(insn.MethodIndex, out var off) || off == 0)
                        continue;

                    dexBuf = PatchDexInsns(dexBuf, checked((int)off), insn.Data);
                    restoredMethods++;

                    string cls = methodMeta.TryGetValue(insn.MethodIndex, out var c) ? c : "Unknown";

                    string hexList = string.Join(",", insn.Data.Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));
                    if (!classGroups.TryGetValue(cls, out var list))
                    {
                        list = new List<Dictionary<string, object>>();
                        classGroups[cls] = list;
                    }

                    list.Add(new Dictionary<string, object>
                    {
                        ["methodId"] = insn.MethodIndex,
                        ["code"] = $"[{hexList}]"
                    });
                }

                dexBuf = FixDexHeaders(dexBuf);
                dexBuffers[dexName] = dexBuf;

                restored.Add(new RestoredInfo { DexIndex = dexIdx, DexFile = dexName, RestoredMethods = restoredMethods });

                // build json format similar to PHP output: [ { "Class.Name": [ ... ] }, ... ]
                var dexJson = new List<Dictionary<string, object>>();
                foreach (var kv in classGroups)
                    dexJson.Add(new Dictionary<string, object> { [kv.Key] = kv.Value });

                string jsonName = dexName + ".json";
                jsonFiles.Add(jsonName);

                jsonBuffers[jsonName] = JsonSerializer.Serialize(dexJson, new JsonSerializerOptions
                {
                    WriteIndented = true
                });
            }

            var elapsed = (DateTime.UtcNow - start).TotalSeconds;

            var summary = new SummaryInfo
            {
                ExtractedFiles = extractedFiles,
                DexFiles = dexEntries,
                JsonFiles = jsonFiles,
                Restored = restored,
                ElapsedSeconds = Math.Round(elapsed, 3),
                MultiDex = new MultiDexHeader { Version = multi.Version, DexCount = multi.DexCount },
                Notes = notes
            };

            return new PipelineResult
            {
                Summary = summary,
                DexBuffers = dexBuffers,
                JsonBuffers = jsonBuffers
            };
        }

        // ========================= Core pipeline helpers =========================

        public static byte[] ExtractEmbeddedZipFromDex(byte[] dex)
        {
            // ZIP local file header signature: 50 4B 03 04
            var sig = new byte[] { 0x50, 0x4B, 0x03, 0x04 };
            int idx = IndexOf(dex, sig);
            if (idx < 0) throw new InvalidOperationException("Embedded ZIP signature not found in DEX");
            return dex.AsSpan(idx).ToArray();
        }

        public static MultiDexCode ReadMultiDexCode(byte[] buf)
        {
            int off = 0;
            Ensure(buf, off, 2, "version");
            ushort version = ReadUInt16LE(buf, off); off += 2;

            Ensure(buf, off, 2, "dexCount");
            ushort dexCount = ReadUInt16LE(buf, off); off += 2;

            var dexOffsets = new uint[dexCount];
            for (int i = 0; i < dexCount; i++)
            {
                Ensure(buf, off, 4, $"dexOffsets[{i}]");
                dexOffsets[i] = ReadUInt32LE(buf, off);
                off += 4;
            }

            var dexCodes = new List<DexCode>();

            for (int di = 0; di < dexOffsets.Length; di++)
            {
                uint dexOff = dexOffsets[di];
                Ensure(buf, (int)dexOff, 2, $"dex[{di}].methodCount");

                int p = checked((int)dexOff);
                ushort methodCount = ReadUInt16LE(buf, p); p += 2;

                var instructions = new List<InstructionEntry>();

                for (int mi = 0; mi < methodCount; mi++)
                {
                    if (p + 8 > buf.Length) break;

                    uint methodIndex = ReadUInt32LE(buf, p); p += 4;
                    uint dataSize = ReadUInt32LE(buf, p); p += 4;

                    if ((long)p + dataSize > buf.Length) break;

                    var data = new byte[dataSize];
                    Buffer.BlockCopy(buf, p, data, 0, (int)dataSize);
                    p += (int)dataSize;

                    instructions.Add(new InstructionEntry { MethodIndex = methodIndex, Size = dataSize, Data = data });
                }

                dexCodes.Add(new DexCode { MethodCount = methodCount, Instructions = instructions });
            }

            return new MultiDexCode
            {
                Version = version,
                DexCount = dexCount,
                DexOffsets = dexOffsets,
                DexCodes = dexCodes,
                Warnings = new List<string>()
            };
        }

        public static byte[] PatchDexInsns(byte[] dex, int insnsOff, byte[] codeBytes)
        {
            if (insnsOff < 0 || insnsOff + codeBytes.Length > dex.Length)
                throw new InvalidOperationException("Patch would write out of bounds");

            var outBuf = (byte[])dex.Clone();
            Buffer.BlockCopy(codeBytes, 0, outBuf, insnsOff, codeBytes.Length);
            return outBuf;
        }

        public static byte[] FixDexHeaders(byte[] dex)
        {
            var outBuf = (byte[])dex.Clone();

            // file_size @ 0x20
            BinaryPrimitives.WriteUInt32LittleEndian(outBuf.AsSpan(0x20, 4), (uint)outBuf.Length);

            // signature (SHA-1) over everything from 0x20 to end, stored at 0x0C (20 bytes)
            using (var sha1 = SHA1.Create())
            {
                var sig = sha1.ComputeHash(outBuf, 0x20, outBuf.Length - 0x20);
                Buffer.BlockCopy(sig, 0, outBuf, 0x0C, 20);
            }

            // checksum (adler32) over everything from 0x0C to end, stored at 0x08 (4 bytes)
            uint sum = Adler32(outBuf.AsSpan(0x0C));
            BinaryPrimitives.WriteUInt32LittleEndian(outBuf.AsSpan(0x08, 4), sum);

            return outBuf;
        }

        // ========================= DEX parsing =========================

        private static DexParseResult ParseDex(byte[] dex)
        {
            var h = ReadHeader(dex);
            var strings = ParseStrings(dex, h);
            var types = ParseTypes(dex, h, strings);
            var methodIds = ReadMethodIds(dex, h, strings, types);

            var codeOffByMethodIdx = new Dictionary<int, uint>();

            for (uint i = 0; i < h.ClassDefsSize; i++)
            {
                int baseOff = checked((int)h.ClassDefsOff + (int)i * 32);
                uint classDataOff = ReadUInt32LE(dex, baseOff + 24);
                if (classDataOff != 0)
                {
                    ParseClassDataForMethodCodeOffs(dex, checked((int)classDataOff),
                        (methodIdx, codeOff) => codeOffByMethodIdx[methodIdx] = codeOff);
                }
            }

            var methods = new List<DexMethodInfo>();
            foreach (var m in methodIds)
            {
                var proto = ParseProto(dex, m.ProtoIdx, h, strings, types);
                uint? codeOff = codeOffByMethodIdx.TryGetValue(m.MethodIdx, out var co) ? co : (uint?)null;
                uint? insnsOff = codeOff.HasValue ? (codeOff.Value + 16u) : (uint?)null;

                methods.Add(new DexMethodInfo
                {
                    MethodIdx = m.MethodIdx,
                    ClassDescriptor = m.ClassDescriptor,
                    Name = m.Name,
                    ProtoShorty = proto.ProtoShorty,
                    ReturnType = proto.ReturnType,
                    ParamTypes = proto.ParamTypes,
                    CodeOff = codeOff,
                    InsnsOff = insnsOff
                });
            }

            return new DexParseResult
            {
                Header = h,
                Strings = strings,
                Types = types,
                Methods = methods,
                CodeOffByMethodIdx = codeOffByMethodIdx
            };
        }

        private static DexHeader ReadHeader(byte[] dex)
        {
            return new DexHeader
            {
                FileSize = ReadUInt32LE(dex, 0x20),

                StringIdsSize = ReadUInt32LE(dex, 0x38),
                StringIdsOff = ReadUInt32LE(dex, 0x3C),

                TypeIdsSize = ReadUInt32LE(dex, 0x40),
                TypeIdsOff = ReadUInt32LE(dex, 0x44),

                ProtoIdsSize = ReadUInt32LE(dex, 0x48),
                ProtoIdsOff = ReadUInt32LE(dex, 0x4C),

                MethodIdsSize = ReadUInt32LE(dex, 0x58),
                MethodIdsOff = ReadUInt32LE(dex, 0x5C),

                ClassDefsSize = ReadUInt32LE(dex, 0x60),
                ClassDefsOff = ReadUInt32LE(dex, 0x64),
            };
        }

        private static List<string> ParseStrings(byte[] dex, DexHeader h)
        {
            var strings = new List<string>(checked((int)h.StringIdsSize));
            for (uint i = 0; i < h.StringIdsSize; i++)
            {
                uint stringDataOff = ReadUInt32LE(dex, checked((int)h.StringIdsOff + (int)i * 4));
                strings.Add(ReadString(dex, checked((int)stringDataOff)));
            }
            return strings;
        }

        private static string ReadString(byte[] dex, int stringDataOff)
        {
            int off = stringDataOff;
            var (value, newOff) = ReadUleb128(dex, off);
            _ = value; // utf16 length not required here
            off = newOff;

            int end = Array.IndexOf(dex, (byte)0x00, off);
            if (end < 0) throw new InvalidOperationException("Unterminated string_data_item");
            return Encoding.UTF8.GetString(dex, off, end - off);
        }

        private static List<string> ParseTypes(byte[] dex, DexHeader h, List<string> strings)
        {
            var types = new List<string>(checked((int)h.TypeIdsSize));
            for (uint i = 0; i < h.TypeIdsSize; i++)
            {
                uint descriptorIdx = ReadUInt32LE(dex, checked((int)h.TypeIdsOff + (int)i * 4));
                types.Add(strings[checked((int)descriptorIdx)]);
            }
            return types;
        }

        private static List<DexMethodId> ReadMethodIds(byte[] dex, DexHeader h, List<string> strings, List<string> types)
        {
            var methods = new List<DexMethodId>(checked((int)h.MethodIdsSize));
            for (uint i = 0; i < h.MethodIdsSize; i++)
            {
                int baseOff = checked((int)h.MethodIdsOff + (int)i * 8);
                ushort classIdx = ReadUInt16LE(dex, baseOff);
                ushort protoIdx = ReadUInt16LE(dex, baseOff + 2);
                uint nameIdx = ReadUInt32LE(dex, baseOff + 4);

                var m = new DexMethodId
                {
                    MethodIdx = checked((int)i),
                    ClassIdx = classIdx,
                    ProtoIdx = protoIdx,
                    NameIdx = nameIdx,
                    ClassDescriptor = types[classIdx],
                    Name = strings[checked((int)nameIdx)]
                };
                methods.Add(m);
            }
            return methods;
        }

        private sealed class ProtoInfo
        {
            public string ProtoShorty = "";
            public string ReturnType = "";
            public List<string> ParamTypes = new();
        }

        private static ProtoInfo ParseProto(byte[] dex, ushort protoIdx, DexHeader h, List<string> strings, List<string> types)
        {
            int baseOff = checked((int)h.ProtoIdsOff + protoIdx * 12);
            uint shortyIdx = ReadUInt32LE(dex, baseOff);
            uint returnTypeIdx = ReadUInt32LE(dex, baseOff + 4);
            uint paramsOff = ReadUInt32LE(dex, baseOff + 8);

            var info = new ProtoInfo
            {
                ProtoShorty = strings[checked((int)shortyIdx)],
                ReturnType = types[checked((int)returnTypeIdx)],
            };

            if (paramsOff != 0)
            {
                int po = checked((int)paramsOff);
                uint size = ReadUInt32LE(dex, po);
                int p = po + 4;

                for (uint i = 0; i < size; i++)
                {
                    ushort typeIdx = ReadUInt16LE(dex, p);
                    p += 2;
                    info.ParamTypes.Add(types[typeIdx]);
                }
            }

            return info;
        }

        private static void ParseClassDataForMethodCodeOffs(byte[] dex, int classDataOff, Action<int, uint> callback)
        {
            int off = classDataOff;

            var (staticFieldsSize, off1) = ReadUleb128(dex, off); off = off1;
            var (instanceFieldsSize, off2) = ReadUleb128(dex, off); off = off2;
            var (directMethodsSize, off3) = ReadUleb128(dex, off); off = off3;
            var (virtualMethodsSize, off4) = ReadUleb128(dex, off); off = off4;

            void SkipEncodedFieldList(uint n)
            {
                uint fieldIdx = 0;
                for (uint i = 0; i < n; i++)
                {
                    var (delta, o1) = ReadUleb128(dex, off); fieldIdx += delta; off = o1;
                    var (_, o2) = ReadUleb128(dex, off); off = o2; // accessFlags
                }
            }

            SkipEncodedFieldList(staticFieldsSize);
            SkipEncodedFieldList(instanceFieldsSize);

            void ReadEncodedMethodList(uint n)
            {
                uint methodIdx = 0;
                for (uint i = 0; i < n; i++)
                {
                    var (delta, o1) = ReadUleb128(dex, off); methodIdx += delta; off = o1;
                    var (_, o2) = ReadUleb128(dex, off); off = o2; // accessFlags
                    var (codeOff, o3) = ReadUleb128(dex, off); off = o3;

                    if (codeOff != 0)
                        callback(checked((int)methodIdx), codeOff);
                }
            }

            ReadEncodedMethodList(directMethodsSize);
            ReadEncodedMethodList(virtualMethodsSize);
        }

        // ========================= Utilities =========================

        private static string ClassNameFromDescriptor(string desc)
        {
            // Lcom/foo/Bar; -> com.foo.Bar
            if (desc.StartsWith("L", StringComparison.Ordinal) && desc.EndsWith(";", StringComparison.Ordinal))
                desc = desc.Substring(1, desc.Length - 2);
            return desc.Replace('/', '.');
        }

        private static bool IsClassesDex(string name)
        {
            // classes.dex, classes2.dex, classes10.dex...
            if (string.IsNullOrEmpty(name)) return false;
            name = name.Replace('\\', '/');
            var file = name.Split('/').Last();
            if (!file.EndsWith(".dex", StringComparison.OrdinalIgnoreCase)) return false;
            if (!file.StartsWith("classes", StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }

        private static int NaturalDexSort(string a, string b)
        {
            int na = DexNumber(a);
            int nb = DexNumber(b);
            int cmp = na.CompareTo(nb);
            if (cmp != 0) return cmp;
            return string.Compare(a, b, StringComparison.Ordinal);
        }

        private static int DexNumber(string path)
        {
            string file = path.Replace('\\', '/').Split('/').Last();
            // classes.dex -> 1, classes2.dex -> 2
            var lower = file.ToLowerInvariant();
            if (!lower.StartsWith("classes") || !lower.EndsWith(".dex")) return int.MaxValue;

            string mid = lower.Substring("classes".Length, lower.Length - "classes".Length - ".dex".Length);
            if (string.IsNullOrEmpty(mid)) return 1;
            if (int.TryParse(mid, NumberStyles.Integer, CultureInfo.InvariantCulture, out int n)) return n;
            return int.MaxValue;
        }

        private static (uint value, int offset) ReadUleb128(byte[] buf, int offset)
        {
            uint result = 0;
            int shift = 0;

            while (true)
            {
                if (offset >= buf.Length) break;
                byte cur = buf[offset++];
                result |= (uint)(cur & 0x7F) << shift;
                if ((cur & 0x80) == 0) break;
                shift += 7;
            }

            return (result, offset);
        }

        private static ushort ReadUInt16LE(byte[] buf, int offset)
        {
            Ensure(buf, offset, 2, "ReadUInt16LE");
            return BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan(offset, 2));
        }

        private static uint ReadUInt32LE(byte[] buf, int offset)
        {
            Ensure(buf, offset, 4, "ReadUInt32LE");
            return BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(offset, 4));
        }

        private static void Ensure(byte[] buf, int offset, int need, string label)
        {
            if (offset < 0 || offset + need > buf.Length)
                throw new InvalidOperationException($"{label}: need {need} bytes at offset {offset}, but buffer length is {buf.Length}");
        }

        private static uint Adler32(ReadOnlySpan<byte> data)
        {
            const uint MOD = 65521;
            uint a = 1, b = 0;

            for (int i = 0; i < data.Length; i++)
            {
                a = (a + data[i]) % MOD;
                b = (b + a) % MOD;
            }
            return (b << 16) | a;
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0) return 0;
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { ok = false; break; }
                }
                if (ok) return i;
            }
            return -1;
        }
    }
}