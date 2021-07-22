br = bv.get_view_of_type('Raw')
vmStr = 'vermagic='
symtabPrefix = '__symtab'
reltabPrefix = '__reltab'
tempTabFill = 'data'
#    0:	0xe1a08008 	mov	r8, r8

# ex: fetchStructMem('gnu_reloc', 'info', 'r_type')

def fetchStructMem(targetVar, *args):
    netOffset = 0
    netSize = 0
    targVarSym = br.get_symbol_by_raw_name(targetVar)
    targVarVar = br.get_data_var_at(targVarSym.address)
    nextTargVar = targVarVar.type.structure
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
    # we have broken out, optimistically we are at the most primitive type
    retValue = br.read(targVarSym.address + netOffset, netSize)
    return retValue

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

def findNextReloc(relocName):
    result = -1
    Elf32_Rel_typeS = br.get_type_by_name("Elf32_Rel")
    symTabEntrySz = br.sections['.symtab'].entry_size
    relTextEntrySz = br.sections['.rel.text'].entry_size
    curReltabAddress = br.sections['.rel.text'].start
    while curReltabAddress < br.sections['.rel.text'].end:
        potentialSym = fetchStructMem(relocName, 'info', 'r_sym')
        potentialSym = int.from_bytes(potentialSym, byteorder='little', signed=False)
        potentialSym = potentialSym * symTabEntrySz + br.sections['.symtab'].start
        symEntName = br.get_symbol_at(potentialSym)
        potentialName = fetchStructMem(symEntName.name, 'st_name')
        potentialName = int.from_bytes(potentialName, byteorder='little', signed=False)
        potentialName = potentialName + br.sections['.strtab'].start
        symReadName = br.get_string_at(potentialName)
        curReltabAddress += relTextEntrySz

    return result

def fetchName(symIndex):
    symTabSz = br.sections['.symtab'].end - br.sections['.symtab'].start
    symTabEntrySz = br.sections['.symtab'].entry_size

    symNet = symIndex * symTabEntrySz + br.sections['.symtab'].start


def patchReloc(relocName):
    relTextSz = br.sections['.rel.text'].end - br.sections['.rel.text'].start
    relTextEntrySz = br.sections['.rel.text'].entry_size
    count = 0
    relEntries = relTextSz / relTextEntrySz
    while count < relTextSz:
        
        count += relTextEntrySz

def patchVermagic(kernVers):
    modinfoSz = br.sections['.modinfo'].end - br.sections['.modinfo'].start
    modinfoStr = br.get_strings(br.sections['.modinfo'].start, modinfoSz)
    for i in modinfoStr:
        if i[0:len(vmStr)] == vmStr:
            br.write(i.start + len(vmStr), kernVers)