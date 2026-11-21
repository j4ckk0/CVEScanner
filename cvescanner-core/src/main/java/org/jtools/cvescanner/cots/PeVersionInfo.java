package org.jtools.cvescanner.cots;

/*-
 * #%L
 * CVEScanner
 * %%
 * Copyright (C) 2026 jtools.org
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The version information of a Windows DLL or EXE (its VS_VERSIONINFO resource): ProductName, ProductVersion,
 * FileVersion, CompanyName. The file is read, never run nor loaded: a few bounded reads — its headers, its section
 * table, its resource directory, the resource itself —, every offset and size checked against the file, any
 * inconsistency giving no information rather than an error. A file is not trusted for being a binary.
 */
public final class PeVersionInfo {

    /** What a version resource says; a value it does not give is null. */
    public record Info(String productName, String productVersion, String fileVersion, String companyName) {}

    private static final int MAX_SECTIONS = 96;
    private static final int MAX_ENTRIES = 512;
    private static final int MAX_RESOURCE = 1 << 20;
    private static final int RT_VERSION = 16;

    private final FileChannel channel;
    private final long size;

    private PeVersionInfo(FileChannel channel) throws IOException {
        this.channel = channel;
        this.size = channel.size();
    }

    /** The file's version information; empty when it is no PE file, has none, or holds anything inconsistent. */
    public static Optional<Info> read(Path file) {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            return new PeVersionInfo(channel).info();
        } catch (IOException | RuntimeException _) {
            return Optional.empty();
        }
    }

    /** Bytes at an offset of the file, little-endian; null when they are not all there. */
    private ByteBuffer at(long offset, int length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > size) return null;
        ByteBuffer buffer = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            if (channel.read(buffer, offset + buffer.position()) < 0) return null;
        }
        return buffer.flip();
    }

    private Optional<Info> info() throws IOException {
        ByteBuffer dos = at(0, 64);
        if (dos == null || dos.getShort(0) != 0x5A4D) return Optional.empty();   // "MZ"
        long pe = Integer.toUnsignedLong(dos.getInt(0x3C));
        ByteBuffer coff = at(pe, 24);
        if (coff == null || coff.getInt(0) != 0x00004550) return Optional.empty();   // "PE\0\0"
        int sections = Short.toUnsignedInt(coff.getShort(6));
        int optionalSize = Short.toUnsignedInt(coff.getShort(20));
        if (sections == 0 || sections > MAX_SECTIONS) return Optional.empty();
        long optional = pe + 24;
        ByteBuffer opt = at(optional, optionalSize);
        if (opt == null || optionalSize < 2) return Optional.empty();
        int magic = Short.toUnsignedInt(opt.getShort(0));
        int directories = magic == 0x20B ? 112 : magic == 0x10B ? 96 : -1;   // PE32+, PE32
        if (directories < 0 || optionalSize < directories + 3 * 8) return Optional.empty();
        long resourceRva = Integer.toUnsignedLong(opt.getInt(directories + 2 * 8));
        if (resourceRva == 0) return Optional.empty();
        ByteBuffer table = at(optional + optionalSize, sections * 40);
        if (table == null) return Optional.empty();
        long[][] map = new long[sections][];
        for (int i = 0; i < sections; i++) {
            int s = i * 40;
            map[i] = new long[] {Integer.toUnsignedLong(table.getInt(s + 12)),            // virtual address
                    Math.max(Integer.toUnsignedLong(table.getInt(s + 8)), Integer.toUnsignedLong(table.getInt(s + 16))),
                    Integer.toUnsignedLong(table.getInt(s + 20))};                       // raw data's offset
        }
        long resources = offset(map, resourceRva);
        if (resources < 0) return Optional.empty();
        // type 16 (version), then its first name, then its first language: a data entry
        long name = child(resources, resources, RT_VERSION, true);
        long language = name < 0 ? -1 : child(resources, name, 0, false);
        long entry = language < 0 ? -1 : child(resources, language, 0, false);
        if (entry < 0) return Optional.empty();
        ByteBuffer data = at(entry, 16);
        if (data == null) return Optional.empty();
        long blob = offset(map, Integer.toUnsignedLong(data.getInt(0)));
        int length = data.getInt(4);
        if (blob < 0 || length <= 0 || length > MAX_RESOURCE) return Optional.empty();
        ByteBuffer version = at(blob, length);
        return version == null ? Optional.empty() : strings(version);
    }

    /** The file offset of an address of the loaded image; -1 when no section holds it. */
    private long offset(long[][] map, long rva) {
        for (long[] s : map) if (rva >= s[0] && rva < s[0] + s[1]) return s[2] + (rva - s[0]);
        return -1;
    }

    /**
     * In the resource directory at dir, the entry of this id (or the first one, wanted false): the file offset of its
     * subdirectory, or of its data entry at the last level; -1 when there is none.
     */
    private long child(long resources, long dir, int id, boolean wanted) throws IOException {
        ByteBuffer head = at(dir, 16);
        if (head == null) return -1;
        int count = Short.toUnsignedInt(head.getShort(12)) + Short.toUnsignedInt(head.getShort(14));
        if (count == 0 || count > MAX_ENTRIES) return -1;
        ByteBuffer entries = at(dir + 16, count * 8);
        if (entries == null) return -1;
        for (int i = 0; i < count; i++) {
            int nameOrId = entries.getInt(i * 8), target = entries.getInt(i * 8 + 4);
            if (wanted && (nameOrId < 0 || nameOrId != id)) continue;
            long offset = resources + (target & 0x7FFFFFFFL);
            return offset > dir || target >= 0 ? offset : -1;   // a subdirectory before its parent would loop
        }
        return -1;
    }

    /** The strings of a VS_VERSIONINFO block: those of its StringFileInfo's first table. */
    private static Optional<Info> strings(ByteBuffer b) {
        Map<String, String> values = new HashMap<>();
        Block root = Block.at(b, 0, b.limit());
        if (root == null || !root.key().equals("VS_VERSION_INFO")) return Optional.empty();
        for (Block child : root.children(b))
            if (child.key().equals("StringFileInfo"))
                for (Block stringTable : child.children(b))
                    for (Block string : stringTable.children(b))
                        values.putIfAbsent(string.key(), string.text(b));
        if (values.isEmpty()) return Optional.empty();
        return Optional.of(new Info(values.get("ProductName"), values.get("ProductVersion"), values.get("FileVersion"),
                values.get("CompanyName")));
    }

    /** A block of a version resource: its key, its value's place, its children's, its end. */
    private record Block(String key, int type, int value, int valueLength, int children, int end) {

        static Block at(ByteBuffer b, int offset, int limit) {
            if (offset < 0 || offset + 6 > limit) return null;
            int length = Short.toUnsignedInt(b.getShort(offset));
            int valueLength = Short.toUnsignedInt(b.getShort(offset + 2));
            int type = Short.toUnsignedInt(b.getShort(offset + 4));
            int end = offset + length;
            if (length < 6 || end > limit) return null;
            int p = offset + 6;
            var key = new StringBuilder();
            while (p + 2 <= end && b.getShort(p) != 0) {
                key.append((char) b.getShort(p));
                p += 2;
            }
            p = align(p + 2);
            int bytes = type == 1 ? valueLength * 2 : valueLength;
            if (p + bytes > end) bytes = Math.max(0, end - p);
            return new Block(key.toString(), type, p, bytes, align(p + bytes), end);
        }

        List<Block> children(ByteBuffer b) {
            var out = new ArrayList<Block>();
            for (int p = children; p < end && out.size() < MAX_ENTRIES; ) {
                Block c = at(b, p, end);
                if (c == null) break;
                out.add(c);
                p = align(c.end());
            }
            return out;
        }

        /** The value as text: UTF-16, up to its terminating zero. */
        String text(ByteBuffer b) {
            byte[] raw = new byte[valueLength];
            b.get(value, raw);
            String s = new String(raw, StandardCharsets.UTF_16LE);
            int zero = s.indexOf('\0');
            return (zero >= 0 ? s.substring(0, zero) : s).strip();
        }

        private static int align(int p) {
            return (p + 3) & ~3;
        }
    }
}
