// Ghidra headless post-script: decompile functions to C and write them to a file.
// Run by Invoke-NativeDecompile.ps1 via analyzeHeadless -postScript. Java (not Python) so
// it needs no PyGhidra; Ghidra compiles it on the fly with the JDK.
//
// Script args:
//   [0] output .c file path (required)
//   [1] optional case-insensitive function-name substring filter
//   [2] optional case-insensitive STRING filter: only export functions that reference a
//       defined string containing this text (anchor on a known log message, registry value,
//       or CSP node path when symbols are absent and names are FUN_*)
//
//@category Rudy
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ExportDecompiled extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ExportDecompiled: missing output path argument");
            return;
        }
        String outPath = args[0];
        String nameFilter = (args.length > 1 && args[1] != null && !args[1].isEmpty()) ? args[1].toLowerCase() : null;
        String stringFilter = (args.length > 2 && args[2] != null && !args[2].isEmpty()) ? args[2].toLowerCase() : null;

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Listing listing = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        PrintWriter w = new PrintWriter(outPath, "UTF-8");
        try {
            w.printf("// Decompiled from %s by Ghidra (Tier 4)%n", currentProgram.getName());
            w.printf("// filters: name=%s string=%s%n%n", nameFilter, stringFilter);

            int exported = 0;
            for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (nameFilter != null && !fn.getName().toLowerCase().contains(nameFilter)) {
                    continue;
                }

                List<String> strs = null;
                if (stringFilter != null) {
                    strs = referencedStrings(fn, listing, refMgr);
                    boolean hit = false;
                    for (String s : strs) {
                        if (s.toLowerCase().contains(stringFilter)) { hit = true; break; }
                    }
                    if (!hit) {
                        continue;
                    }
                }

                DecompileResults res = decomp.decompileFunction(fn, 90, monitor);
                if (res == null || !res.decompileCompleted()) {
                    continue;
                }

                w.printf("// ==== %s @ %s ====%n", fn.getName(), fn.getEntryPoint());
                if (strs != null && !strs.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    int n = 0;
                    for (String s : strs) {
                        if (n > 0) sb.append(" | ");
                        sb.append(s);
                        if (++n >= 8) break;
                    }
                    w.printf("// references strings: %s%n", sb.toString());
                }
                w.print(res.getDecompiledFunction().getC());
                w.print("\n\n");
                exported++;
            }
            w.printf("// %d function(s) exported%n", exported);
            println("ExportDecompiled: wrote " + exported + " function(s) to " + outPath);
        } finally {
            w.close();
        }
    }

    private List<String> referencedStrings(Function fn, Listing listing, ReferenceManager refMgr) {
        List<String> found = new ArrayList<String>();
        AddressIterator addrs = fn.getBody().getAddresses(true);
        while (addrs.hasNext()) {
            Address a = addrs.next();
            for (Reference ref : refMgr.getReferencesFrom(a)) {
                Data data = listing.getDataAt(ref.getToAddress());
                if (data != null && data.hasStringValue()) {
                    Object v = data.getValue();
                    if (v != null) {
                        found.add(v.toString());
                    }
                }
            }
        }
        return found;
    }
}
