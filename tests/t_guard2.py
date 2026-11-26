import os
import sys, types
fake = types.ModuleType("serial"); fake.SerialException = Exception
tools = types.ModuleType("serial.tools"); lp = types.ModuleType("serial.tools.list_ports")
lp.comports = lambda: []; tools.list_ports = lp; fake.tools = tools
sys.modules.update({"serial": fake, "serial.tools": tools, "serial.tools.list_ports": lp})
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tsa_adaption_reset as m
class L:
    def event(self, *a): pass
g = m.TxGuard(L())
for ok in ("1001", "1081", "3E00", "0100", "0902", "03", "07", "22F190",
           "22 F1 8C", "22f187"):
    g.assert_tx_allowed(ok)
for bad in ("1085", "1002", "1003", "1087", "1082", "1089", "1090", "1092", "1086",
            "2701", "2E0102", "3B01", "3401", "3601", "1101", "3101", "3114",
            "302207", "14FFFFFF", "04", "1A80", "2101", "3E01", "22F1", "22F19000",
            "", "XYZ", "123"):
    try:
        g.assert_tx_allowed(bad); print("GUARD FAIL", bad); sys.exit(1)
    except m.SafetyError: pass
# no arming / enabling API exists any more
for name in ("arm_reset", "disarm", "_armed_reset"):
    if hasattr(g, name):
        print("FAIL: guard still exposes", name); sys.exit(1)
print("GUARD2_OK")
