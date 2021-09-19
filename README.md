This GHIDRA script queries symgrate and renames all functions found to
the name returned by symgrate.

Copy it to `~/ghidra_scripts` and run it in the Script Manager.

Very quickly and poorly hacked on by me. Doesn't bother checking
if you've manually renamed the function. Renames it anyway. Doesn't
batch up queries to the server. But, it works.


