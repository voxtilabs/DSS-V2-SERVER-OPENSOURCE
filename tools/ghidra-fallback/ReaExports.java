// ReaExports.java - Ghidra headless fallback (no MCP): lista exports (external entry points).
// Uso: analyzeHeadless <projdir> <proj> -import <bin> -noanalysis -scriptPath <dir> -postScript ReaExports.java [max]
//@category REA
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ReaExports extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        int max = args.length > 0 ? Integer.parseInt(args[0]) : 5000;
        int n = 0;
        SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
        while (it.hasNext() && n < max) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                println("EXP " + s.getName() + " @ " + s.getAddress());
                n++;
            }
        }
        println("REA-EXPORTS total=" + n);
    }
}
