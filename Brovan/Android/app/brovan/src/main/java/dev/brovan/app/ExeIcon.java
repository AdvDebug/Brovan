package dev.brovan.app;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;

final class ExeIcon {

    private static final int RT_ICON = 3;
    private static final int RT_GROUP_ICON = 14;
    private static final int RT_VERSION = 16;
    private static final int MAX_VERSION_BYTES = 64 * 1024;
    private static final int VERSION_BLOCK_HEADER = 6;
    private static final int STRING_FILE_INFO_DEPTH = 1;
    private static final int VERSION_STRING_DEPTH = 3;
    private static final int MAX_EDGE = 256;
    private static final int MAX_IMAGE_BYTES = 8 * 1024 * 1024;
    private static final int SECTION_FIELDS = 4;

    private final RandomAccessFile file;
    private final long length;

    private long[] sections = new long[0];
    private long resourceRoot;

    private ExeIcon(RandomAccessFile file) throws IOException {
        this.file = file;
        this.length = file.length();
    }

    static Bitmap extract(File exe) {
        try (RandomAccessFile handle = new RandomAccessFile(exe, "r")) {
            return new ExeIcon(handle).best();
        } catch (IOException | RuntimeException unusable) {
            return null;
        }
    }

    static String[] versionNames(File exe) {
        String[] names = new String[2];
        try (RandomAccessFile handle = new RandomAccessFile(exe, "r")) {
            new ExeIcon(handle).readVersionNames(names);
        } catch (IOException | RuntimeException unusable) {
            return new String[2];
        }
        return names;
    }

    private void readVersionNames(String[] names) throws IOException {
        if (!openResources()) {
            return;
        }

        long entry = firstLeaf(firstChild(subDirectory(resourceRoot, RT_VERSION)));
        if (entry < 0) {
            return;
        }

        byte[] data = bytes(toOffset(u32(entry)), (int) Math.min(u32(entry + 4), MAX_VERSION_BYTES));
        if (data != null) {
            collectNames(data, 0, data.length, 0, names);
        }
    }

    // VS_VERSIONINFO, StringFileInfo, StringTable and String share one layout: length, value length, type,
    // a UTF-16 key, then the value and the children, each aligned to 4 bytes.
    private static void collectNames(byte[] data, int at, int end, int depth, String[] names) {
        while (at + VERSION_BLOCK_HEADER <= end) {
            int blockLength = int16(data, at);
            if (blockLength < VERSION_BLOCK_HEADER || at + blockLength > end) {
                return;
            }

            int blockEnd = at + blockLength;
            int keyStart = at + VERSION_BLOCK_HEADER;
            int keyEnd = utf16End(data, keyStart, blockEnd);
            String key = new String(data, keyStart, keyEnd - keyStart, StandardCharsets.UTF_16LE);
            boolean text = int16(data, at + 4) == 1;
            int valueLength = int16(data, at + 2) * (text ? 2 : 1);
            int value = Math.min(align4(keyEnd + 2), blockEnd);
            int valueEnd = Math.min(value + valueLength, blockEnd);

            if (depth == VERSION_STRING_DEPTH) {
                store(key, data, value, valueEnd, names);
            } else if (depth != STRING_FILE_INFO_DEPTH || key.equals("StringFileInfo")) {
                collectNames(data, Math.min(align4(valueEnd), blockEnd), blockEnd, depth + 1, names);
            }

            at = align4(blockEnd);
        }
    }

    private static void store(String key, byte[] data, int from, int to, String[] names) {
        int slot = key.equals("FileDescription") ? 0 : key.equals("ProductName") ? 1 : -1;
        if (slot < 0 || names[slot] != null) {
            return;
        }

        int end = utf16End(data, from, to);
        String value = new String(data, from, end - from, StandardCharsets.UTF_16LE).trim();
        if (!value.isEmpty()) {
            names[slot] = value;
        }
    }

    private static int utf16End(byte[] data, int from, int to) {
        while (from + 2 <= to && int16(data, from) != 0) {
            from += 2;
        }

        return from;
    }

    private static int align4(int at) {
        return (at + 3) & ~3;
    }

    private Bitmap best() throws IOException {
        if (!openResources()) {
            return null;
        }

        long icons = subDirectory(resourceRoot, RT_ICON);
        if (icons < 0) {
            return null;
        }

        long entry = firstLeaf(firstChild(subDirectory(resourceRoot, RT_GROUP_ICON)));
        if (entry < 0) {
            return null;
        }

        return fromGroup(bytes(toOffset(u32(entry)), (int) u32(entry + 4)), icons);
    }

    private boolean openResources() throws IOException {
        if (u16(0) != 0x5A4D) {
            return false;
        }

        long pe = u32(0x3C);
        if (u32(pe) != 0x00004550) {
            return false;
        }

        int sectionCount = u16(pe + 6);
        int optionalSize = u16(pe + 20);
        long optional = pe + 24;
        int magic = u16(optional);

        long directoryCountAt;
        long directories;

        if (magic == 0x10B) {
            directoryCountAt = optional + 92;
            directories = optional + 96;
        } else if (magic == 0x20B) {
            directoryCountAt = optional + 108;
            directories = optional + 112;
        } else {
            return false;
        }

        if (u32(directoryCountAt) < 3) {
            return false;
        }

        long resourceRva = u32(directories + 2 * 8);
        if (resourceRva == 0) {
            return false;
        }

        readSections(optional + optionalSize, sectionCount);

        resourceRoot = toOffset(resourceRva);
        return resourceRoot >= 0;
    }

    private Bitmap fromGroup(byte[] group, long icons) throws IOException {
        if (group == null || group.length < 6) {
            return null;
        }

        int count = int16(group, 4);
        int bestWidth = -1;
        int bestBits = -1;
        int bestId = -1;

        for (int i = 0; i < count; i++) {
            int at = 6 + i * 14;
            if (at + 14 > group.length) {
                break;
            }

            int width = group[at] & 0xFF;
            if (width == 0) {
                width = 256;
            }

            int bits = int16(group, at + 10);
            int id = int16(group, at + 12);

            if (width > bestWidth || (width == bestWidth && bits > bestBits)) {
                bestWidth = width;
                bestBits = bits;
                bestId = id;
            }
        }

        if (bestId < 0) {
            return null;
        }

        long image = subDirectory(icons, bestId);
        if (image < 0) {
            return null;
        }

        long entry = firstLeaf(image);
        if (entry < 0) {
            return null;
        }

        byte[] data = bytes(toOffset(u32(entry)), (int) u32(entry + 4));
        if (data == null) {
            return null;
        }

        if (data.length > 8 && (data[0] & 0xFF) == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') {
            return BitmapFactory.decodeByteArray(data, 0, data.length);
        }

        return decodeDib(data);
    }

    private void readSections(long at, int count) throws IOException {
        if (count <= 0 || count > 96) {
            return;
        }

        sections = new long[count * SECTION_FIELDS];

        for (int i = 0; i < count; i++) {
            long header = at + i * 40L;
            sections[i * SECTION_FIELDS] = u32(header + 12);
            sections[i * SECTION_FIELDS + 1] = u32(header + 8);
            sections[i * SECTION_FIELDS + 2] = u32(header + 20);
            sections[i * SECTION_FIELDS + 3] = u32(header + 16);
        }
    }

    private long toOffset(long rva) {
        for (int i = 0; i < sections.length; i += SECTION_FIELDS) {
            long start = sections[i];
            long span = Math.max(sections[i + 1], sections[i + 3]);

            if (rva >= start && rva < start + span) {
                long offset = sections[i + 2] + (rva - start);
                return offset < length ? offset : -1;
            }
        }

        return -1;
    }

    private long subDirectory(long directory, int id) throws IOException {
        if (directory < 0) {
            return -1;
        }

        int named = u16(directory + 12);
        int numbered = u16(directory + 14);

        for (int i = named; i < named + numbered; i++) {
            long entry = directory + 16 + i * 8L;
            if (u32(entry) != id) {
                continue;
            }

            long offset = u32(entry + 4);
            return (offset & 0x80000000L) != 0 ? resourceRoot + (offset & 0x7FFFFFFFL) : -1;
        }

        return -1;
    }

    private long firstChild(long directory) throws IOException {
        if (directory < 0 || u16(directory + 12) + u16(directory + 14) == 0) {
            return -1;
        }

        long offset = u32(directory + 16 + 4);
        return (offset & 0x80000000L) != 0 ? resourceRoot + (offset & 0x7FFFFFFFL) : -1;
    }

    private long firstLeaf(long directory) throws IOException {
        if (directory < 0 || u16(directory + 12) + u16(directory + 14) == 0) {
            return -1;
        }

        long offset = u32(directory + 16 + 4);
        return (offset & 0x80000000L) != 0 ? -1 : resourceRoot + offset;
    }

    private static Bitmap decodeDib(byte[] data) {
        if (data.length < 40) {
            return null;
        }

        int headerSize = int32(data, 0);
        int width = int32(data, 4);
        int height = int32(data, 8) / 2;
        int bits = int16(data, 14);
        int compression = int32(data, 16);

        if (headerSize < 40 || headerSize > data.length || compression != 0) {
            return null;
        }

        if (width <= 0 || height <= 0 || width > MAX_EDGE || height > MAX_EDGE) {
            return null;
        }

        int paletteCount = int32(data, 32);
        if (bits <= 8 && paletteCount == 0) {
            paletteCount = 1 << bits;
        }

        int paletteAt = headerSize;
        int pixelsAt = paletteAt + paletteCount * 4;
        int xorStride = ((width * bits + 31) / 32) * 4;
        int andStride = ((width + 31) / 32) * 4;

        if (paletteCount < 0 || pixelsAt < 0 || pixelsAt > data.length
                || pixelsAt + xorStride * height > data.length) {
            return null;
        }

        int andAt = pixelsAt + xorStride * height;
        boolean hasAnd = andAt + andStride * height <= data.length;

        int[] pixels = new int[width * height];
        boolean anyAlpha = false;

        for (int y = 0; y < height; y++) {
            int row = pixelsAt + (height - 1 - y) * xorStride;

            for (int x = 0; x < width; x++) {
                int argb;

                switch (bits) {
                    case 32: {
                        int at = row + x * 4;
                        int alpha = data[at + 3] & 0xFF;
                        anyAlpha |= alpha != 0;
                        argb = (alpha << 24) | ((data[at + 2] & 0xFF) << 16)
                                | ((data[at + 1] & 0xFF) << 8) | (data[at] & 0xFF);
                        break;
                    }

                    case 24: {
                        int at = row + x * 3;
                        argb = 0xFF000000 | ((data[at + 2] & 0xFF) << 16)
                                | ((data[at + 1] & 0xFF) << 8) | (data[at] & 0xFF);
                        break;
                    }

                    case 8:
                        argb = palette(data, paletteAt, paletteCount, data[row + x] & 0xFF);
                        break;

                    case 4: {
                        int pair = data[row + x / 2] & 0xFF;
                        argb = palette(data, paletteAt, paletteCount, (x & 1) == 0 ? pair >> 4 : pair & 0x0F);
                        break;
                    }

                    case 1: {
                        int octet = data[row + x / 8] & 0xFF;
                        argb = palette(data, paletteAt, paletteCount, (octet >> (7 - (x & 7))) & 1);
                        break;
                    }

                    default:
                        return null;
                }

                pixels[y * width + x] = argb;
            }
        }

        if (bits == 32 && !anyAlpha) {
            for (int i = 0; i < pixels.length; i++) {
                pixels[i] |= 0xFF000000;
            }
        }

        if ((bits != 32 || !anyAlpha) && hasAnd) {
            for (int y = 0; y < height; y++) {
                int row = andAt + (height - 1 - y) * andStride;

                for (int x = 0; x < width; x++) {
                    if (((data[row + x / 8] >> (7 - (x & 7))) & 1) != 0) {
                        pixels[y * width + x] = 0;
                    }
                }
            }
        }

        return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888);
    }

    private static int palette(byte[] data, int at, int count, int index) {
        int entry = at + index * 4;
        if (index >= count || entry < 0 || entry + 4 > data.length) {
            return 0xFF000000;
        }

        return 0xFF000000 | ((data[entry + 2] & 0xFF) << 16)
                | ((data[entry + 1] & 0xFF) << 8) | (data[entry] & 0xFF);
    }

    private byte[] bytes(long at, int count) throws IOException {
        if (at < 0 || count <= 0 || count > MAX_IMAGE_BYTES) {
            return null;
        }

        require(at, count);
        byte[] data = new byte[count];
        file.seek(at);
        file.readFully(data);
        return data;
    }

    private int u16(long at) throws IOException {
        require(at, 2);
        file.seek(at);
        return (file.read() & 0xFF) | ((file.read() & 0xFF) << 8);
    }

    private long u32(long at) throws IOException {
        require(at, 4);
        file.seek(at);
        return (file.read() & 0xFFL) | ((file.read() & 0xFFL) << 8)
                | ((file.read() & 0xFFL) << 16) | ((file.read() & 0xFFL) << 24);
    }

    private void require(long at, int count) throws IOException {
        if (at < 0 || count < 0 || at + count > length) {
            throw new IOException("resource offset outside the file");
        }
    }

    private static int int16(byte[] data, int at) {
        if (at < 0 || at + 2 > data.length) {
            return 0;
        }

        return (data[at] & 0xFF) | ((data[at + 1] & 0xFF) << 8);
    }

    private static int int32(byte[] data, int at) {
        if (at < 0 || at + 4 > data.length) {
            return 0;
        }

        return (data[at] & 0xFF) | ((data[at + 1] & 0xFF) << 8)
                | ((data[at + 2] & 0xFF) << 16) | ((data[at + 3] & 0xFF) << 24);
    }
}
