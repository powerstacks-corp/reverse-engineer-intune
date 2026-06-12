# Ghidra headless post-script: decompile functions to C and write them to a file.
# Run by Invoke-NativeDecompile.ps1 via analyzeHeadless -postScript.
#
# Script args:
#   [0] output .c file path (required)
#   [1] optional case-insensitive function-name substring filter
#   [2] optional case-insensitive STRING filter: only export functions that reference a
#       defined string containing this text (anchor on a known log message, registry value,
#       or CSP node path when symbols are absent and names are FUN_*)
#
# @category Rudy

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def referenced_strings(program, func):
    """Return the defined-data strings referenced from within a function's body."""
    found = []
    listing = program.getListing()
    body = func.getBody()
    ref_mgr = program.getReferenceManager()
    addrs = body.getAddresses(True)
    for addr in addrs:
        for ref in ref_mgr.getReferencesFrom(addr):
            data = listing.getDataAt(ref.getToAddress())
            if data is not None and data.hasStringValue():
                try:
                    found.append(str(data.getValue()))
                except Exception:
                    pass
    return found


def run():
    args = getScriptArgs()
    if len(args) < 1:
        print("ExportDecompiled: missing output path argument")
        return
    out_path = args[0]
    name_filter = args[1].lower() if len(args) > 1 and args[1] else None
    string_filter = args[2].lower() if len(args) > 2 and args[2] else None

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    funcs = list(currentProgram.getFunctionManager().getFunctions(True))
    f = open(out_path, "w")
    f.write("// Decompiled from %s by Ghidra (Tier 4)\n" % currentProgram.getName())
    f.write("// %d total functions; filters: name=%s string=%s\n\n" % (len(funcs), name_filter, string_filter))

    exported = 0
    for fn in funcs:
        if monitor.isCancelled():
            break
        if name_filter and name_filter not in fn.getName().lower():
            continue
        strings = None
        if string_filter:
            strings = referenced_strings(currentProgram, fn)
            if not any(string_filter in s.lower() for s in strings):
                continue
        res = decomp.decompileFunction(fn, 90, monitor)
        if res is None or not res.decompileCompleted():
            continue
        f.write("// ==== %s @ %s ====\n" % (fn.getName(), fn.getEntryPoint()))
        if strings:
            hits = [s for s in strings if not string_filter or string_filter in s.lower()]
            if hits:
                f.write("// references strings: %s\n" % " | ".join(hits[:8]))
        f.write(res.getDecompiledFunction().getC())
        f.write("\n\n")
        exported += 1

    f.write("// %d function(s) exported\n" % exported)
    f.close()
    print("ExportDecompiled: wrote %d function(s) to %s" % (exported, out_path))


run()
