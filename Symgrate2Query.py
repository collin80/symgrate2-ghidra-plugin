#Quick symgrate.com client script for Thumb2 symbol recovery.
#@author Travis Goodspeed
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


## This is a Ghidra plugin in Jython 2.7 that queries the Symgrate2
## database, in order to recognize standard functions from a variety
## of embedded ARM development kits.

## Rewriting it in Java might be a good idea.  Who knows?

import httplib;
from ghidra.program.model.symbol.SourceType import *


#Must match the server.
LEN=18

def queryfns(conn, q):
    """Queries the server for a dozen or more functions."""
    conn.request("GET", "/fns?"+q) 
    r1 = conn.getresponse()
    # print r1.status, r1.reason
    # 200 OK ?
    toret="";
    if r1.status==200:
        data = r1.read();
        if len(data)>2:
            toret += data.strip();

    return toret;

fncount=currentProgram.getFunctionManager().getFunctionCount();
monitor.initialize(fncount);

# Iterate over all the functions, querying from the database and printing them.
f = getFirstFunction()
fnhandled=0;

conn = httplib.HTTPConnection("symgrate.com",80)

qstr="";

while f is not None:
    iname=f.getName();
    adr=f.getEntryPoint();
    adrstr="%x"%adr.offset;
    res=None;

    B=getBytes(adr, LEN);
    bstr="";
    for b in B: bstr+="%02x"%(0x00FF&b)

    qstr+="%s=%s&"%(adrstr,bstr)
    #if fnhandled&0x3F==0 or f is None:
    res=queryfns(conn,qstr);
    toks = res.split(' ');
    if len(toks) > 1:
        print "Renaming function at " + toks[0] + " to " + toks[1];
        f.setName(toks[1], USER_DEFINED);
    monitor.setProgress(fnhandled);
    qstr="";
    f = getFunctionAfter(f)
    
    fnhandled+=1;

conn.close();

