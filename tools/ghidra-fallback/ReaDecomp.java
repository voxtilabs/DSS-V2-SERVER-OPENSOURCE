// ReaDecomp.java - Ghidra headless fallback (no MCP): decompila la funcion que contiene una VA.
// Uso: analyzeHeadless <projdir> <proj> -import <bin> -scriptPath <dir> -postScript ReaDecomp.java <0xVA> [timeoutSec]
// Imprime: REA-DECOMP func=<name> entry=<entry> y el C de la funcion.
//@category REA
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

public class ReaDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[0]);
        int timeout = args.length > 1 ? Integer.parseInt(args[1]) : 180;
        Function f = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (f == null) { println("REA-DECOMP func=NONE at " + addr); return; }
        println("REA-DECOMP func=" + f.getName() + " entry=" + f.getEntryPoint());
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        DecompileResults res = di.decompileFunction(f, timeout, new ConsoleTaskMonitor());
        if (res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("REA-DECOMP FAILED: " + res.getErrorMessage());
        }
        di.dispose();
    }
}
