// Ghidra headless PRE-script: point the PDB analyzer at Microsoft's public symbol server
// and cache downloads locally, so native functions come back NAMED (for example
// StoreServerLastTime) instead of FUN_*. This is what makes Tier 4 read like source, the
// way Rudy's teardowns do. Java, so it needs no PyGhidra. Runs before auto-analysis, which
// is where the PDB gets downloaded and applied.
//
// The Microsoft server is registered as a TRUSTED server, which Ghidra searches during
// analysis without any further option or prompt. If the config fails (offline, msdl
// unreachable), the script logs it and lets analysis continue unsymbolized.
//
// Script args:
//   [0] local symbol cache directory (created and initialized if missing)
//
//@category Rudy
import ghidra.app.script.GhidraScript;
import pdb.PdbPlugin;
import pdb.symbolserver.HttpSymbolServer;
import pdb.symbolserver.LocalSymbolStore;
import pdb.symbolserver.SymbolServer;
import pdb.symbolserver.SymbolServerService;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class EnableMsSymbols extends GhidraScript {

    @Override
    public void run() throws Exception {
        try {
            String[] args = getScriptArgs();
            File cacheDir = (args.length > 0 && args[0] != null && !args[0].isEmpty())
                ? new File(args[0])
                : new File(System.getProperty("user.home"), ".ghidra-symbols");
            cacheDir.mkdirs();

            if (!LocalSymbolStore.isLocalSymbolStoreLocation(cacheDir.getAbsolutePath())) {
                LocalSymbolStore.create(cacheDir, 1);
            }
            LocalSymbolStore localStore = new LocalSymbolStore(cacheDir);

            List<SymbolServer> servers = new ArrayList<SymbolServer>();
            servers.add(HttpSymbolServer.createTrusted("https://msdl.microsoft.com/download/symbols/"));

            SymbolServerService svc = new SymbolServerService(localStore, servers);
            PdbPlugin.saveSymbolServerServiceConfig(svc);

            println("EnableMsSymbols: Microsoft symbol server configured (trusted). Cache: "
                + cacheDir.getAbsolutePath());
        } catch (Throwable t) {
            println("EnableMsSymbols: could not configure symbols (" + t
                + "). Continuing without symbols; functions will be FUN_*.");
        }
    }
}
