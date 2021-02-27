# Ghidra Scripts
Another ghidra scripts repository.  

## Fix Free Flow  
This fixes problems with a non-returning function being improperly detected, and while you fixed the function to return, Ghidra doesn't fix the flow.  
This can lead to it not disasembling code, which can mess up disassembly and other things.  
This script fixes the flow of the current function you're focused on.  
This works with the address to the function that is being called (mine was `_free`!). If you look at the top of the function you'll see:
`Address BAD_FUNCTION_ADDRESS = this.toAddr(0x005dd138);`  
Simply change that value to whatever you want.  
It defaults to replacing `CALL_RETURN` flow with `NONE` (aka `-DEFAULT-` in the Ghidra UI), but those can be modified to.  
I personally bind this to a key because I have to do it sufficiently often.  
If your program is smaller (aka didn't take that long to analyze) and you haven't yet done notable amounts, I'd rec fixing the analysis rather than trying to bulldoze past it.  
  
## Into This Call  
This is a simple script that changes the current functions calling convention to `__thiscall`. I had to do this a lot, and so rather than clicking function signature, `F` to edit function, clicking dropdown, and clicking the calling convention, I just use this bound to a simple keybind.  
The string for the calling convention can be changed to whatever you want. Dunno what it does if the convention is invalid.  
  
## Generate Enum  
This parses a JSON file for an enum.  
It asks for the enum name (it will overwrite the enum if there wasn't any errors), enum size (1, 2, 4, 8 like the enum editor), and the json file (doesn't care about extension) to load.  
Format is:  
```json
[
    {
        "id": value,
        "text": "The_name_of_the_variant"
    },
    {
        "id": value2,
        "text": "The_name_of_the_variant2"
    },
]
```
Actually, just realized that size 8 may not work. Since GSON (the json impl that Ghidra ships with) I think messes with enums of that size.  
This helps with loading enums that are generated from somewhere else. Perhaps from a list you have (like a long list of defines into json into an enum!).  
My use case was that a dll exported a ton of strings for localization and so it would load the strings by their resource index. Wrote a script to extract all the strings, generate the json for each value and string (replacing characters which I wasn't sure ghidra would display properly), and use this GenerateEnum script to import.