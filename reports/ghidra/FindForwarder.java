import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class FindForwarder extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();

        String[] keywords = {"signForwarderHelloMAC", "verifyForwarderResponseMAC",
            "hmacSHA256Hex", "randomForwarderNonce", "doForwarderControlFetch",
            "fetchForwarderControlPlane", "tryForwarderControlEndpoints",
            "fwdControlResponseToFixedSet", "forwarderControlPSK"};

        println("=== 搜索函数符号 ===");
        SymbolIterator symbols = st.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();
            for (String kw : keywords) {
                if (name.toLowerCase().contains(kw.toLowerCase())) {
                    Address addr = sym.getAddress();
                    Function func = fm.getFunctionAt(addr);
                    if (func != null) {
                        println("FOUND: " + name + " @ " + addr);
                    }
                    break;
                }
            }
        }

        // 搜索所有 forwarder 相关符号
        println("\n=== 所有 forwarder 符号 ===");
        symbols = st.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();
            if (name.contains("forwarder") || name.contains("fwdControl") || name.contains("fwdHello")) {
                println("  " + name + " @ " + sym.getAddress());
            }
        }

        // 搜索 hmac 相关
        println("\n=== hmac 符号 ===");
        symbols = st.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();
            if (name.toLowerCase().contains("hmac") && name.toLowerCase().contains("sha256")) {
                println("  " + name + " @ " + sym.getAddress());
            }
        }
    }
}
