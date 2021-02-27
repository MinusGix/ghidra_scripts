//TODO write a description for this script
//@author 
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
import java.io.File;
import com.google.gson.*;
import com.google.gson.stream.JsonWriter;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

public class GenerateEnum extends GhidraScript {
    static int SUITABLY_BIG_SIZE = 1024 * 1024 * 256; // 256 megabytes

    private class Entry {
	public final int id;
	public final String text;
	public Entry(int id, String text) {
		this.id = id;
		this.text = text;
	}
    }

    public void run() throws Exception {
	String name = askString("Enum Name", "Enum Name (NOTE: Any existing enums with the same name would be replaced!):");
	if (name == null) {
		printf("No name chosen, presuming that it was cancelled.");
		return;
	}
	
	Integer[] sizesArr = {1, 2, 4, 8};
	List<Integer> sizes = Arrays.asList(sizesArr);
	int size = askChoice("Enum Size", "Enum Size:", sizes, 1);

	File file = askFile("Input JSON File", "Parse as Enum");
	if (file == null) {
		printf("Failed to get file, presuming that it was cancelled.");
		return;
	}

	if (file.length() >= this.SUITABLY_BIG_SIZE) {
		boolean shouldContinue = askYesNo("Open File?", "This file is rather large (greater than 256mb!), are you sure you want to open it?");
		if (!shouldContinue) {
			printf("Cancelled by user. File too large.");
			return;
		}
	}

	if (file.isDirectory()) {
		printf("Expected a file, got a directory.");
		return;
	}

	if (!file.canRead()) {
		printf("Can not read file.");
		return;
	}

	// Unsure if there is a better way..
	String text = Files.readString(file.toPath());
	
// We don't appear to be able to tell it to allow hex, which I failed to make it use..
	Gson gson = new GsonBuilder()
		.setLenient()
		.create();
	Entry[] entries = gson.fromJson(text, Entry[].class);
	printf("Length: %d", entries.length);

	ProgramBasedDataTypeManager manager = this.currentProgram.getDataTypeManager();

	EnumDataType enm = new EnumDataType(name, size);
	for (Entry entry : entries) {
		printf("%s - %d\n", entry.text, entry.id);
		enm.add(entry.text, entry.id);
	}
	// TODO: It'd be nice to query the user if they want it replaced.
	manager.addDataType(enm, DataTypeConflictHandler.REPLACE_HANDLER);
    }

}
