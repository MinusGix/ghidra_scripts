// A script to easily convert functions into __thiscall.
//@author MinusGix
//@category _NEW_
//@keybinding
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class IntoThisCall extends GhidraScript {
	static String convention = "__thiscall";
	static boolean requireNoCustomVariableStorage = true;
	public void run() throws Exception {
		Address address = this.currentAddress;
		if (address == null) {
			println("Failed to get current address, it was null.");
			return;
		}
		Function func = this.getFunctionContaining(address);
		if (func == null) {
			println("Failed to get function that contains the current address. Make sure it is actually a function and not a label!");
			return;
		}
		if (func.hasVarArgs()) {
			println("This function has var-args, which I don't believe are supported in __thiscall!");
			return;
		}
		if (func.hasCustomVariableStorage() && this.requireNoCustomVariableStorage) {
			boolean shouldRemove = askYesNo("Remove Custom Variable Storage?", "Should this remove custom variable storage to apply the calling convention?");
			if (shouldRemove) {
				func.setCustomVariableStorage(false);
				if (func.hasCustomVariableStorage()) {
					throw new Exception("Tried to set custom variable storage to false but it was not changed!");
				}
				// fallthrough
			} else {
				return;
			}
		}
		func.setCallingConvention(this.convention);
	}
}
