// Fixes up calls to _free that have bad flow
//@author MinusGix
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar asdf.gif

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
import java.util.Set;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class FixFreeFlow extends GhidraScript {
	//static String BAD_FUNCTION_NAME = "_free";
	static FlowOverride BAD_FLOW = FlowOverride.CALL_RETURN;
	static FlowOverride NEW_FLOW = FlowOverride.NONE;
	public void run() throws Exception {
		Address BAD_FUNCTION_ADDRESS = this.toAddr(0x005dd138);

		if (this.currentAddress == null) {
			println("Current Address was null.");
			return;
		}
		Function currentFunction = validateFunction(this.getFunctionContaining(this.currentAddress));
		if (currentFunction == null) {
			return;
		}

		ConsoleTaskMonitor taskMonitor = new ConsoleTaskMonitor();
		taskMonitor.setMessage("Finding all functions that are being called..");

		// TODO: Might it be better to get the functions that call the bad function
		// and then see if the one we're in is in the list?
		/*Set<Function> calledFunctions = currentFunction.getCalledFunctions(taskMonitor);
		boolean hasCallToBad = false;
		for (Function func : calledFunctions) {
			if (isBadFunction(func)) {
				hasCallToBad = true;
				break;
			}
		}

		if (!hasCallToBad) {
			println("This function does not call the bad function");
			return;
		}*/

		ReferenceManager referenceManager = this.currentProgram.getReferenceManager();		

		// Get an AddressSetView of the function
		AddressSetView body = currentFunction.getBody();

		// Iterate over all the addresses that reference somewhere else.
		AddressIterator iter = referenceManager
			.getReferenceSourceIterator(body, true);
		for (Address address : iter) {
			// Filter for all the addresses that match the function we are looking for.
			Reference reference = referenceManager.getReference(address, BAD_FUNCTION_ADDRESS, 0);
			if (reference != null) {
				Instruction instruction = this.getInstructionAt(address);
				if (instruction == null) {
					printf("Failed to get instruction at %s, skipping..\n", address.toString());
					continue;
				}
				if (instruction.getFlowOverride() == BAD_FLOW) {
					printf("Address %s had the bad flow, fixing..\n", address.toString());
					// Update the flow
					instruction.setFlowOverride(NEW_FLOW);
					// Disassemble the code after this instruction..
					// TODO: Able to specify that you don't want it to auto disassemble?
					Address endingAddress = instruction.getMaxAddress().next();
					DisassembleCommand cmd = new DisassembleCommand(endingAddress, null, true);
					cmd.applyTo(this.currentProgram, taskMonitor);
				}
			}
		}

		/*Instruction instruction = this.getFirstInstruction(currentFunction);
		while (instruction != null) {
			FlowOverride flowOverride = instruction.getFlowOverride();
			if (flowOverride == BAD_FLOW_AFTER) {
				println(instruction.toString());
			}
			instruction = instruction.getNext();
		}*/

		/*DecompInterface ifc = new DecompInterface();

		// Options

		ifc.openProgram(program);

		taskMonitor.setMessage("Decompiling..");
		DecompileResults res = ifc.decompileFunction(currentFunc, 0, taskMonitor);
		if (!res.decompileCompleted()) {
			printf("Compilation failed: %s\n", res.getErrorMessage());
			return;
		}

		HighFunction hfunc = res.getHighFunction();
		if (hfunc == null) {
			printf("Failed to get high function from decompiler output");
			return;
		}*/
	}
	
	/*private boolean isBadFunction(Function func) {
		if (func == null) {
			return false;
		}
		return func.getName().equals(this.BAD_FUNCTION_NAME);
	}*/

	private Function validateFunction(Function func) {
		if (func == null) {
			println("Could not get function");
			return null;
		}

		if (func.isExternal()) {
			println("This does not operate on external functions");
			return null;
		}

		if (func.isThunk()) {
			boolean shouldPassthrough = askYesNo("Operate on Function that this is a thunk of?", "Should we find the thunked function that this refers to?");
			if (shouldPassthrough) {
				return validateFunction(func.getThunkedFunction(true));
			}
			println("Chose not to passthrough from thunk function");
			return null;
		}

		return func;
	}
}
