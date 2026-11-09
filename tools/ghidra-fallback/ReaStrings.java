// ReaStrings.java - Ghidra headless fallback (no MCP), funciona con -noanalysis:
// 1) escanea los bloques de memoria en crudo (ASCII + UTF-16LE) por el regex dado
// 2) para cada match calcula su VA y busca xrefs rip-relative (lea/mov 48/4C 8D/8B modrm=..05 disp32)
//    dentro de los bloques ejecutables, e imprime la funcion contenedora si existe.
// Uso: analyzeHeadless <projdir> <proj> -import <bin> -noanalysis -scriptPath <dir> -postScript ReaStrings.java <regex> [maxHits]
//@category REA
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class ReaStrings extends GhidraScript {

    private static String extractAscii(byte[] b, int start, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < Math.min(b.length, start + max); i++) {
            int c = b[i] & 0xff;
            if (c >= 0x20 && c < 0x7f) sb.append((char) c);
            else break;
        }
        return sb.toString();
    }

    private static String extractUtf16(byte[] b, int start, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = start; i + 1 < Math.min(b.length, start + max * 2); i += 2) {
            int c = (b[i] & 0xff) | ((b[i + 1] & 0xff) << 8);
            if (c >= 0x20 && c < 0x7f) sb.append((char) c);
            else break;
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Pattern pat = Pattern.compile(args.length > 0 ? args[0] : ".*", Pattern.CASE_INSENSITIVE);
        int maxHits = args.length > 1 ? Integer.parseInt(args[1]) : 200;
        Memory mem = currentProgram.getMemory();
        MemoryBlock[] blocks = mem.getBlocks();
        List<long[]> hits = new ArrayList<>();
        List<String> vals = new ArrayList<>();
        int found = 0;
        for (MemoryBlock blk : blocks) {
            if (blk.getType() == MemoryBlock.EXTERNAL_BLOCK) continue;
            long start = blk.getStart().getOffset();
            long szL = blk.getSize();
            if (szL <= 0 || szL > 64L * 1024 * 1024) continue;
            int size = (int) szL;
            byte[] buf = new byte[size];
            mem.getBytes(blk.getStart(), buf);
            int i = 0;
            while (i < size && found < maxHits) {
                if (buf[i] >= 0x20 && buf[i] < 0x7f) {
                    String s = extractAscii(buf, i, 512);
                    if (s.length() >= 4 && pat.matcher(s).find()) {
                        hits.add(new long[]{start + i, 1});
                        vals.add(s.length() > 300 ? s.substring(0, 300) : s);
                        found++;
                    }
                    i += Math.max(1, s.length());
                } else i++;
            }
            i = 0;
            while (i + 1 < size && found < maxHits) {
                int c = (buf[i] & 0xff) | ((buf[i + 1] & 0xff) << 8);
                if (c >= 0x20 && c < 0x7f && (buf[i + 1] & 0xff) == 0) {
                    String s = extractUtf16(buf, i, 256);
                    if (s.length() >= 4 && pat.matcher(s).find()) {
                        hits.add(new long[]{start + i, 2});
                        vals.add(s.length() > 300 ? s.substring(0, 300) : s);
                        found++;
                    }
                    i += Math.max(2, s.length() * 2);
                } else i += 2;
            }
        }
        List<byte[]> codeBufs = new ArrayList<>();
        List<Long> codeStarts = new ArrayList<>();
        for (MemoryBlock cb : blocks) {
            if (!cb.isExecute() || cb.getType() == MemoryBlock.EXTERNAL_BLOCK) continue;
            long cs = cb.getStart().getOffset();
            long cszL = cb.getSize();
            if (cszL <= 0 || cszL > 256L * 1024 * 1024) continue;
            int csz = (int) cszL;
            byte[] c = new byte[csz];
            mem.getBytes(cb.getStart(), c);
            codeBufs.add(c);
            codeStarts.add(cs);
        }
        println("REA-STRINGS hits=" + found);
        for (int k = 0; k < hits.size(); k++) {
            long off = hits.get(k)[0];
            int enc = (int) hits.get(k)[1];
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
            println("STR enc=" + enc + " " + a + " | " + vals.get(k));
            for (int bi = 0; bi < codeBufs.size(); bi++) {
                byte[] c = codeBufs.get(bi);
                long cs = codeStarts.get(bi);
                for (int p = 0; p + 7 <= c.length; p++) {
                    int b0 = c[p] & 0xff, b1 = c[p + 1] & 0xff, modrm = c[p + 2] & 0xff;
                    boolean isLea = (b0 == 0x48 || b0 == 0x4c) && b1 == 0x8d;
                    boolean isMov = (b0 == 0x48 || b0 == 0x4c) && b1 == 0x8b;
                    if (!isLea && !isMov) continue;
                    if ((modrm & 0xc7) != 0x05) continue;
                    int disp = (c[p+3]&0xff) | ((c[p+4]&0xff)<<8) | ((c[p+5]&0xff)<<16) | ((c[p+6]&0xff)<<24);
                    long target = cs + p + 7 + disp;
                    if (target == off) {
                        Address from = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(cs + p);
                        Function f = currentProgram.getFunctionManager().getFunctionContaining(from);
                        println("  XREF " + (isLea ? "lea" : "mov") + " from=" + from + " func=" + (f != null ? f.getName() + "@" + f.getEntryPoint() : "?"));
                    }
                }
            }
        }
    }
}
