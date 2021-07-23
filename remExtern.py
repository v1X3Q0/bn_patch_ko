br = bv.get_view_of_type('Raw')
vmStr = 'vermagic='
symtabPrefix = '__symtab'
reltabPrefix = '__reltab'
versPrefix = '__version'
tempTabFill = 'data'
MOV_R8_R8 = "\x08\x80\xa0\xe1"
#    0:	0xe1a08008 	mov	r8, r8

# This is essentially a retrieve for an arbitrary type, though it
# is mostly meant to be used against structs to access members. example
# calling convventions are as so:
# 
# ex: fetchStructMem('gnu_reloc', 'info', 'r_type')
def fetchStructMem(targetVar, *args):
    netOffset = 0
    netSize = 0
    targVarSym = br.get_symbol_by_raw_name(targetVar)
    targVarVar = br.get_data_var_at(targVarSym.address)
    nextTargVar = targVarVar.type.structure
    if nextTargVar != None:
        # iterate struct members
        for i in args:
            curTargVar = nextTargVar
            # for each member in the current struct being observed
            for eachMem in curTargVar.members:
                # if the struct member's name is the target arg
                if eachMem.name == i:
                    netOffset += eachMem.offset
                    netSize = eachMem.type.width
                    if eachMem.type.structure != None:
                        nextTargVar = eachMem.type.structure
                    break
    else:
        netSize = targVarVar.type.width
    # we have broken out, optimistically we are at the most primitive type
    retValue = br.read(targVarSym.address + netOffset, netSize)
    return retValue

def fetchStructMemOff(targetVar, *args):
    netOffset = 0
    netSize = 0
    targVarSym = br.get_symbol_by_raw_name(targetVar)
    targVarVar = br.get_data_var_at(targVarSym.address)
    nextTargVar = targVarVar.type.structure
    if nextTargVar != None:
        # iterate struct members
        for i in args:
            curTargVar = nextTargVar
            # for each member in the current struct being observed
            for eachMem in curTargVar.members:
                # if the struct member's name is the target arg
                if eachMem.name == i:
                    netOffset += eachMem.offset
                    netSize = eachMem.type.width
                    if eachMem.type.structure != None:
                        nextTargVar = eachMem.type.structure
                    break
    else:
        netSize = targVarVar.type.width
    # we have broken out, optimistically we are at the most primitive type
    return [targVarSym.address + netOffset, netSize]

# This routine fills the symbol table. Each encountered symbol is filled with the
# name of the string that it is pointing to, followed by the address of the current
# entry.
def defineSymTab():
    Elf32_Sym_typeS = br.get_type_by_name("Elf32_Sym")
    symTabEntrySz = br.sections['.symtab'].entry_size
    curSymtabAddress = br.sections['.symtab'].start
    while curSymtabAddress < br.sections['.symtab'].end:
        curTempDataName = "{}_{}_{}".format(symtabPrefix, tempTabFill, hex(curSymtabAddress))
        someVarThingSym = Symbol(SymbolType.DataSymbol, curSymtabAddress, curTempDataName)
        br.define_user_symbol(someVarThingSym)
        br.define_user_data_var(curSymtabAddress, Elf32_Sym_typeS)
        potentialName = fetchStructMem(curTempDataName, 'st_name')
        potentialName = int.from_bytes(potentialName, byteorder='little', signed=False)
        if potentialName != 0:
            potentialName = potentialName + br.sections['.strtab'].start
            symReadName = br.get_string_at(potentialName)
            br.undefine_user_symbol(someVarThingSym)
            br.undefine_user_data_var(curSymtabAddress)
            curTempDataName = "{}_{}_{}".format(symtabPrefix, symReadName, hex(curSymtabAddress))
            someVarThingSym = Symbol(SymbolType.DataSymbol, curSymtabAddress, curTempDataName)
            br.define_user_symbol(someVarThingSym)
            br.define_user_data_var(curSymtabAddress, Elf32_Sym_typeS)
        curSymtabAddress += symTabEntrySz

# This routine fills out the relocation table's entries. Every relocation is filled with its
# respective type and named its respective symbol's string.
def defineRelTab():
    defineSymTab()
    Elf32_Rel_typeS = br.get_type_by_name("Elf32_Rel")
    symTabEntrySz = br.sections['.symtab'].entry_size
    relTextEntrySz = br.sections['.rel.text'].entry_size
    curReltabAddress = br.sections['.rel.text'].start
    while curReltabAddress < br.sections['.rel.text'].end:
        curTempDataName = "{}_{}_{}".format(reltabPrefix, tempTabFill, hex(curReltabAddress))
        someVarThingSym = Symbol(SymbolType.DataSymbol, curReltabAddress, curTempDataName)
        br.define_user_symbol(someVarThingSym)
        br.define_user_data_var(curReltabAddress, Elf32_Rel_typeS)
        potentialSym = fetchStructMem(curTempDataName, 'info', 'r_sym')
        potentialSym = int.from_bytes(potentialSym, byteorder='little', signed=False)
        potentialSym = potentialSym * symTabEntrySz + br.sections['.symtab'].start
        symEntName = br.get_symbol_at(potentialSym)
        potentialName = fetchStructMem(symEntName.name, 'st_name')
        potentialName = int.from_bytes(potentialName, byteorder='little', signed=False)
        potentialName = potentialName + br.sections['.strtab'].start
        symReadName = br.get_string_at(potentialName)
        curTempDataName = "{}_{}_{}".format(reltabPrefix, symReadName, hex(curReltabAddress))
        someVarThingSym = Symbol(SymbolType.DataSymbol, curReltabAddress, curTempDataName)
        br.define_user_symbol(someVarThingSym)
        br.define_user_data_var(curReltabAddress, Elf32_Rel_typeS)
        curReltabAddress += relTextEntrySz

def defineExtVers():
    Elf32_Vers_typeS = br.get_type_by_name("Elf32_Vers")
    versEntrySz = Elf32_Vers_typeS.width
    versAddress = br.sections['__versions'].start
    while versAddress < br.sections['__versions'].end:
        curTempDataName = "{}_{}_{}".format(versPrefix, tempTabFill, hex(versAddress))
        someVarThingSym = Symbol(SymbolType.DataSymbol, versAddress, curTempDataName)
        br.define_user_symbol(someVarThingSym)
        br.define_user_data_var(versAddress, Elf32_Vers_typeS)
        potentialSym = fetchStructMem(curTempDataName, 'ext_name')
        potentialSym = potentialSym.decode("utf-8") 
        potentialSym = str(potentialSym).replace('\x00', '')
        curTempDataName = "{}_{}_{}".format(versPrefix, potentialSym, hex(versAddress))
        someVarThingSym = Symbol(SymbolType.DataSymbol, versAddress, curTempDataName)
        br.define_user_symbol(someVarThingSym)
        br.define_user_data_var(versAddress, Elf32_Vers_typeS)
        versAddress += versEntrySz

def defineAll():
    defineExtVers()
    defineRelTab()

# retrieves the symbol address for the specified string.
# NOTE this value is also the same as SYMTAB_ADDR + ENTRY_SIZE * INDEX
# meaning that if you need the index, just perform the inverse of that
# operation and your get your index.
def findSymByName(symName):
    result = -1
    symTabEntrySz = br.sections['.symtab'].entry_size
    curSymtabAddress = br.sections['.symtab'].start
    while curSymtabAddress < br.sections['.symtab'].end:
        curTempDataName = br.get_symbol_at(curSymtabAddress)
        potentialName = fetchStructMem(curTempDataName.name, 'st_name')
        potentialName = int.from_bytes(potentialName, byteorder='little', signed=False)
        if potentialName != 0:
            potentialName = potentialName + br.sections['.strtab'].start
            symReadName = br.get_string_at(potentialName)
            if str(symName) == str(symReadName):
                result = curSymtabAddress
                break
        curSymtabAddress += symTabEntrySz
    return result

# This routine is meant to locate all relocations used against a specific named
# symbol. If the symbol cannot be found, or there are no relocations, it will
# return -1. 
def findNextReloc(relocName):
    relocList = []
    symRealAddress = findSymByName(relocName)
    symTabEntrySz = br.sections['.symtab'].entry_size
    symRealIndex = (symRealAddress - br.sections['.symtab'].start) / symTabEntrySz
    relTextEntrySz = br.sections['.rel.text'].entry_size
    curReltabAddress = br.sections['.rel.text'].start
    while curReltabAddress < br.sections['.rel.text'].end:
        curTempDataName = br.get_symbol_at(curReltabAddress)
        potentialSym = fetchStructMem(curTempDataName.name, 'info', 'r_sym')
        potentialSym = int.from_bytes(potentialSym, byteorder='little', signed=False)
        if potentialSym == symRealIndex:
            relocList.append(curReltabAddress)
        curReltabAddress += relTextEntrySz
    return relocList

def patchReloc(relocName):
    Elf32_Rel_typeS = br.get_type_by_name("Elf32_Rel")
    relocList = findNextReloc(relocName)
    for i in relocList:
        relocCurrent = br.get_symbol_at(i)
        realOffset = fetchStructMem(relocCurrent.name, 'offset')
        realOffset = int.from_bytes(realOffset, byteorder='little', signed=False)
        realOffset = realOffset + br.sections['.text'].start
        br.write(realOffset, MOV_R8_R8)
        br.write(i, "\x00" * Elf32_Rel_typeS.width)

def patchVermagic(kernVers):
    modinfoSz = br.sections['.modinfo'].end - br.sections['.modinfo'].start
    modinfoStr = br.get_strings(br.sections['.modinfo'].start, modinfoSz)
    strStartList = []
    for i in modinfoStr:
        strStartList.append([i.start, str(i)])
    for i in strStartList:
        if str(i[1][0:len(vmStr)]) == str(vmStr):
            br.write(i[0], kernVers + '\x00')

def patchSymtab(symName):
    symAddr = findSymByName(symName)
    printkAddr = findSymByName('printk')
    curTempDataName = br.get_symbol_at(symAddr)
    printkTempDataName = br.get_symbol_at(printkAddr)
    nameOffset = fetchStructMemOff(curTempDataName.name, 'st_name')
    printkStrValue = fetchStructMem(printkTempDataName.name, 'st_name')
    br.write(nameOffset[0], printkStrValue)
    return 0

def findExtVers(versName):
    result = -1
    Elf32_Vers_typeS = br.get_type_by_name("Elf32_Vers")
    versEntrySz = Elf32_Vers_typeS.width
    versAddress = br.sections['__versions'].start
    while versAddress < br.sections['__versions'].end:
        curTempDataName = br.get_symbol_at(versAddress)
        potentialSym = fetchStructMem(curTempDataName.name, 'ext_name')
        potentialSym = potentialSym.decode("utf-8") 
        potentialSym = str(potentialSym).replace('\x00', '')
        if str(potentialSym) == str(versName):
            result = versAddress
            break
        versAddress += versEntrySz
    return result

def patchExtVers(versName):
    Elf32_Vers_typeS = br.get_type_by_name("Elf32_Vers")
    targExtVers = findExtVers(versName)
    versEntrySz = Elf32_Vers_typeS.width
    br.write(targExtVers, "\x00" * versEntrySz)


# kernVers="vermagic=2.6.36.4brcmarm+ SMP preempt mod_unload ARMv7 "
# kernVers="vermagic=2.6.36.4brcmarm+ SMP preempt mod_unload ARMv7 "
# "__gnu_mcount_nc"
def fixBinary(kernVers, *args):
    patchVermagic(kernVers)    
    for i in args:
        patchReloc(i)
        patchExtVers(i)
        patchSymtab(i)
    return 0

def fetchName(symIndex):
    symTabSz = br.sections['.symtab'].end - br.sections['.symtab'].start
    symTabEntrySz = br.sections['.symtab'].entry_size
    symNet = symIndex * symTabEntrySz + br.sections['.symtab'].start

