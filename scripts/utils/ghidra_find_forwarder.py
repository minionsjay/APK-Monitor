import ghidra.app.decompiler.DecompInterface as DecompInterface
from ghidra.program.model.symbol import SymbolType

prog = currentProgram
listing = prog.getListing()
fm = prog.getFunctionManager()

# 搜索所有包含 forwarder/hello/mac/sign/verify/hmac 的函数符号
keywords = ["signForwarderHelloMAC", "verifyForwarderResponseMAC", "hmacSHA256Hex",
            "randomForwarderNonce", "doForwarderControlFetch", "fetchForwarderControlPlane",
            "tryForwarderControlEndpoints", "fwdControlResponseToFixedSet",
            "forwarderControlPSK", "signForwarder", "verifyForwarder"]

print("=== 搜索函数符号 ===")
for sym in prog.getSymbolTable().getAllSymbols(True):
    name = sym.getName()
    for kw in keywords:
        if kw.lower() in name.lower():
            addr = sym.getAddress()
            func = fm.getFunctionAt(addr)
            if func:
                print(f"FOUND: {name} @ {addr}")
            break

# 也搜索所有包含 "forwarder" 的符号
print("\n=== 所有包含 forwarder 的符号 ===")
for sym in prog.getSymbolTable().getAllSymbols(True):
    name = sym.getName()
    if "forwarder" in name.lower() or "fwdControl" in name or "fwdHello" in name:
        addr = sym.getAddress()
        print(f"  {name} @ {addr}")

print("\n=== 搜索 hmac 相关符号 ===")
for sym in prog.getSymbolTable().getAllSymbols(True):
    name = sym.getName()
    if "hmac" in name.lower() and "sha256" in name.lower():
        addr = sym.getAddress()
        print(f"  {name} @ {addr}")
