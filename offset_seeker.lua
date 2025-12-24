A64 = {};
function A64.SignExtend(num, bitsize)
    local neg = (num & (1 << (bitsize - 1))) == (1 << (bitsize - 1));
    if neg then 
        return (num | (-1 << bitsize));
    else
        return num;
    end
end
A64.Branch = {};
function A64.Branch.Encode(context)
    local ret = 0x0;
    if context.WithLink then
        ret = ret | 0x94000000;
    else
        ret = ret | 0x14000000;
    end
    if context.Offset % 4 ~= 0 then
        error("A64.Branch: Offset % 4 not equals 0");
    end
    if context.Offset > 0x7FFFFFC or context.Offset < -0x7FFFFFC then 
        error("A64.Branch: Offset value is overflow.");
    end
    local offset = context.Offset // 4;
    ret = ret | (offset & 0x3FFFFFF);
    return ret;
end
function A64.Branch.Decode(asm)
    local ret = {};
    if (asm & 0x14000000) ~= 0x14000000 then
        error("Not A64.Branch asm!");
    end
    ret.WithLink = (asm & 0x94000000) == 0x94000000;
    local offset = (asm & 0x1FFFFFF) * 4;
    local OffsetNegative = (asm & 0x2000000) == 0x2000000;
    if OffsetNegative then
        offset = ~0x3FFFFFF | offset;
    end
    ret.Offset = offset;
    return ret;
end
A64.Address = {};
function A64.Address.Encode(context)
    local ret = 0x0;
    ret = ret | 0x10000000;
    if context.OfPage then
        ret = ret | 0x80000000;
    end
    if context.Register > 31 then
        error("Register is too big (> 31) !")
    end
    ret = ret | context.Register;
    local imm = 0x0;
    if context.OfPage then
        imm = context.Offset / 0x1000;
    else
        imm = context.Offset;
    end
    local immlow = (imm & 0x3) << 29;
    local immhi = (imm & 0x1FFFFC) << 3;
    ret = ret | immlow;
    ret = ret | immhi;
    return ret;
end
function A64.Address.Decode(asm)
    local ret = {};
    if (asm & 0x10000000) ~= 0x10000000 then
        error("Not ADR asm byte.");
    end
    ret.OfPage = (asm & 0x80000000) == 0x80000000;
    ret.Register = (asm & 0x1F);
    local immlow = (asm & 0x60000000) >> 29;
    local immhi = (asm & 0xFFFFE0) >> 3;
    local imm = immhi | immlow;
    if (imm & 0x100000) == 0x100000 then
        imm = imm | (~0x1FFFFF);
    end
    if ret.OfPage then
        ret.Offset = imm * 0x1000;
    else
        ret.Offset = imm;
    end
    return ret;
end
A64.LoadRegister = {}
function A64.LoadRegister.Encode(context)
    if context.Register > 31 or context.Base > 31 then
        error("Register/Base is too big (> 31) !")
    end
    local ret = 0x0
    
    ret = ret | 0x39000000
    
    local sizeBits, scale
    if context.Size == 8 then sizeBits, scale = 0, 0
    elseif context.Size == 16 then sizeBits, scale = 1, 1
    elseif context.Size == 32 then sizeBits, scale = 2, 2
    elseif context.Size == 64 then sizeBits, scale = 3, 3
    else
        error("Unsupported size: " .. tostring(context.Size))
    end
    ret = ret | (sizeBits << 30)
    
    local imm12 = (context.Offset >> scale) & 0xFFF
    ret = ret | (imm12 << 10)
    
    ret = ret | (context.Base << 5)
    
    ret = ret | context.Register
    
    
    if context.SignExtend then
        
        ret = ret | (1 << 22)
    end
    return ret
end
function A64.LoadRegister.Decode(asm)
    local ret = {}
    if (asm & 0x39000000) ~= 0x39000000 then
        error("Not LDR (unsigned immediate) asm byte.")
    end
    local sizeBits = (asm >> 30) & 0x3
    local size = ({[0]=8,[1]=16,[2]=32,[3]=64})[sizeBits]
    local scale = ({[0]=0,[1]=1,[2]=2,[3]=3})[sizeBits]
    local imm12 = (asm >> 10) & 0xFFF
    local base = (asm >> 5) & 0x1F
    local reg = asm & 0x1F
    local offset = imm12 << scale
    local signExtend = ((asm >> 22) & 0x1) == 1
    ret.Register = reg
    ret.Base = base
    ret.Offset = offset
    ret.Size = size
    ret.SignExtend = signExtend
    return ret
end
A64.StoreRegister = {}
function A64.StoreRegister.Encode(context)
    if context.Register > 31 or context.Base > 31 then
        error("Register/Base is too big (> 31) !")
    end
    local ret = 0x0
    
    ret = ret | 0x39000000
    
    local sizeBits, scale
    if context.Size == 8 then sizeBits, scale = 0, 0
    elseif context.Size == 16 then sizeBits, scale = 1, 1
    elseif context.Size == 32 then sizeBits, scale = 2, 2
    elseif context.Size == 64 then sizeBits, scale = 3, 3
    else
        error("Unsupported size: " .. tostring(context.Size))
    end
    ret = ret | (sizeBits << 30)
    
    local imm12 = (context.Offset >> scale) & 0xFFF
    ret = ret | (imm12 << 10)
    
    ret = ret | (context.Base << 5)
    
    ret = ret | context.Register
    return ret
end
function A64.StoreRegister.Decode(asm)
    local ret = {}
    if (asm & 0x39000000) ~= 0x39000000 then
        error("Not STR (unsigned immediate) asm byte.")
    end
    local sizeBits = (asm >> 30) & 0x3
    local size = ({[0]=8,[1]=16,[2]=32,[3]=64})[sizeBits]
    local scale = ({[0]=0,[1]=1,[2]=2,[3]=3})[sizeBits]
    local imm12 = (asm >> 10) & 0xFFF
    local base = (asm >> 5) & 0x1F
    local reg = asm & 0x1F
    local offset = imm12 << scale
    ret.Register = reg
    ret.Base = base
    ret.Offset = offset
    ret.Size = size
    return ret
end
A64.StorePair = {}
function A64.StorePair.Encode(context)
    if context.Rt > 31 or context.Rt2 > 31 or context.Rn > 31 then
        error("Register number overflow (>31)")
    end
    local ret = 0x0
    
    ret = ret | 0x29000000
    
    local sizeBits, scale
    if context.Size == 32 then sizeBits, scale = 0, 2
    elseif context.Size == 64 then sizeBits, scale = 1, 3
    else
        error("Unsupported size: " .. tostring(context.Size))
    end
    ret = ret | (sizeBits << 30)
    
    local imm7 = (context.Offset >> scale) & 0x7F
    ret = ret | (imm7 << 15)
    
    local addrMode = 2 
    if context.PreIndex then
        addrMode = 3
    elseif context.PostIndex then
        addrMode = 1
    end
    ret = ret | (addrMode << 23)
    
    ret = ret | (context.Rt2 << 16)
    
    ret = ret | (context.Rn << 5)
    
    ret = ret | context.Rt
    return ret
end
function A64.StorePair.Decode(asm)
    local ret = {}
    if (asm & 0x29000000) ~= 0x29000000 then
        error("Not STP asm byte.")
    end
    local sizeBits = (asm >> 30) & 0x3
    local size = ({[0]=32,[1]=64})[sizeBits]
    local scale = ({[0]=2,[1]=3})[sizeBits]
    local imm7 = (asm >> 15) & 0x7F
    local offset = imm7 << scale
    local addrMode = (asm >> 23) & 0x3
    local preIndex = (addrMode == 3)
    local postIndex = (addrMode == 1)
    local rt2 = (asm >> 16) & 0x1F
    local rn = (asm >> 5) & 0x1F
    local rt = asm & 0x1F
    ret.Rt = rt
    ret.Rt2 = rt2
    ret.Rn = rn
    ret.Offset = offset
    ret.Size = size
    ret.PreIndex = preIndex
    ret.PostIndex = postIndex
    return ret
end
A64.AddImm = {}
function A64.AddImm.Encode(context)
    local ret = 0x11000000;
    ret = ret | context.Rd;
    ret = ret | (context.Rn << 5);
    ret = ret | (context.imm << 10);
    if context.Shift then
        ret = ret | (1 << 22);
    end
    if context.Bit == 64 then
        ret = ret | 0x80000000
    end
    return ret;
end
function A64.AddImm.Decode(asm)
    if (asm & 0x11000000) ~= 0x11000000 then
        error("Not ADD imm asm !");
    end
    local ret = {};
    ret.Rd = (asm & 0x1F);
    ret.Rn = (asm & (0x1F << 5)) >> 5;
    if (asm & 0x80000000) == 0x80000000 then
        ret.Bit = 64;
    else
        ret.Bit = 32;
    end
    ret.Shift = (asm & 0x400000) == 0x400000;
    ret.imm = (asm & 0x3FFC00) >> 10;
    return ret;
end
A64.SubImm = {}
function A64.SubImm.Encode(context)
    local ret = 0x51000000;
    ret = ret | context.Rd;
    ret = ret | (context.Rn << 5);
    ret = ret | (context.imm << 10);
    if context.Shift then
        ret = ret | (1 << 22);
    end
    if context.Bit == 64 then
        ret = ret | 0x80000000
    end
    return ret;
end
function A64.SubImm.Decode(asm)
    if (asm & 0x51000000) ~= 0x51000000 then
        error("Not ADD imm asm !");
    end
    local ret = {};
    ret.Rd = (asm & 0x1F);
    ret.Rn = (asm & (0x1F << 5)) >> 5;
    if (asm & 0x80000000) == 0x80000000 then
        ret.Bit = 64;
    else
        ret.Bit = 32;
    end
    ret.Shift = (asm & 0x400000) == 0x400000;
    ret.imm = (asm & 0x3FFC00) >> 10;
    return ret;
end

function CheckAddressMask32(addr, mask)
    if mask < 0 or mask > 0xFFFFFFFF then error("CheckAddressMask32(): mask overflow.") end
    local value = Memory_Read_uint32(addr);
    return (value & mask) == mask;
end
function __SearchFunctionStart_Matcher(addr)
    local u32Data = Memory_Read_uint32(addr);
    
    local state,result = pcall(A64.SubImm.Decode, u32Data);
    if state then
        if result.Rn == 31 and result.Rd == 31 then 
            return true; 
        end
    end
    
    if (u32Data & 0xA9007BFD) == 0xA9007BFD then
        return true;
    end
    return false;
end
function SearchFunctionStart(addr, range)
    local AddrBegin = addr;
    local AddrEnd = addr + range;
    for p = addr, AddrEnd, 4 do
        if __SearchFunctionStart_Matcher(p) then 
            return p;
        end
    end
    return nil; 
end

ValueSet("__meta_script_version", "int32", 0); 
cocoslibbase = Library_GetBase("libcocos2dcpp.so");
libcocos2dcpp = cocoslibbase;
if cocoslibbase == nil then
    error("Unable to locate 'libcocos2dcpp.so' base address.");
end
ValueSet("userinfo._libname", "string", "libcocos2dcpp.so");
signlocate_userinfo = Memory_FindWithMask(
                          "E0 03 13 AA 68 02 00 F9 88 00 80 52 00 0C 81 3C",
                          cocoslibbase.addr_start, cocoslibbase.addr_end);
if signlocate_userinfo == 0 then error("Unable to find the sign for 'UserInfo'"); end
do
    local funcoff_userinfo = signlocate_userinfo - 0x68;
    funcoff_userinfo = SearchFunctionStart(funcoff_userinfo, 0x28);
    if(funcoff_userinfo ~= nil) then
        funcoff_userinfo = funcoff_userinfo - cocoslibbase.addr_start;
        ValueSet("userinfo._funcoffset", "int32", funcoff_userinfo);
        LogInfo(string.format("userinfo funoff = 0x%X", funcoff_userinfo));
    else
        error("Unable to locate UserInfo function start.");
    end
    
end
ValueSet("userinfo._reg", "int32", 0);
ValueSet("userinfo.uid", "int32", 0xC);
ValueSet("userinfo.friendcode", "int32", 0x11);
ValueSet("userinfo.username", "int32", 0x29);
ValueSet("userinfo.character", "int32", 0x40);
ValueSet("userinfo.ptt", "int32", 0x44);
ValueSet("clearscore._libname", "string", "libcocos2dcpp.so");
signlocate_clearscore = Memory_FindWithMask(
                            "48 02 80 52 A8 03 1A 38 A8 0C 80 52 88 93 0A 78",
                            cocoslibbase.addr_start, cocoslibbase.addr_end);
if signlocate_clearscore == 0 then
    error("Unable to find the sign for 'ClearScore'")
end
do
    local findres = SearchFunctionStart(signlocate_clearscore - 0x104, 0x28);
    local funcoff = findres - cocoslibbase.addr_start;
    if findres ~= nil then
        ValueSet("clearscore._funcoffset", "int32", funcoff);
        LogInfo(string.format("clearscore funoff = 0x%X", funcoff));
    else
        error("Unable to locate Clearscore function start.");
    end
end
ValueSet("clearscore._reg", "int32", 0);
ValueSet("clearscore.songid", "int32", 0x39);
ValueSet("clearscore.diff", "int32", 0x50);
ValueSet("clearscore.maxpure", "int32", 0x14);
ValueSet("clearscore.pure", "int32", 0x18);
ValueSet("clearscore.far", "int32", 0x1C);
ValueSet("clearscore.lost", "int32", 0x20);
ValueSet("clearscore.trackvalue", "int32", 0x28);
ValueSet("clearscore.modifier", "int32", 0x54);
ValueSet("clearscore.time", "int32", 0x30);
ValueSet("clearscore.nosave", "int32", 0x94);
ValueSet("clearscore.score", "int32", 0x10);
ValueSet("clearscore_uploaded._libname", "string", "libcocos2dcpp.so");
do
    local signloc = Memory_FindWithMask("00 64 41 F9 80 01 00 B4 F6 03 01 2A", libcocos2dcpp.addr_start, libcocos2dcpp.addr_end);
    if signloc ~= nil then
        local find = SearchFunctionStart(signloc - 0x30, 0x28);
        if find ~= nil then
            LogInfo(string.format("Clearscore_uploaded: 0x%X", find - libcocos2dcpp.addr_start));
            ValueSet("clearscore_uploaded._funcoffset", "int32", find - libcocos2dcpp.addr_start);
        else
            error("Clearscore_Uploaded: Unable to locate function start.");
        end
    else
        error("Clearscore_Uploaded: Unable to find Mask.");
    end
end
ValueSet("ranklist._libname", "string", "libcocos2dcpp.so");
signlocate_ranklist = Memory_FindWithMask("3F 00 02 EB 40 03 00 54",
                                          cocoslibbase.addr_start,
                                          cocoslibbase.addr_end);
if signlocate_ranklist == 0 then error("Unable to find the sign for 'RankList'"); end
do
    local jmpoff = signlocate_ranklist + 0x78;
	local jmpliboff = jmpoff - cocoslibbase.addr_start;
    local asm_b = A64.Branch.Decode(Memory_Read_uint32(jmpoff));
	local funoff = jmpliboff + asm_b.Offset;
    ValueSet("ranklist._funcoffset", "int32", funoff);
	LogInfo(string.format("ranklist funoff = 0x%X",funoff));
end
ValueSet("ranklist._reg_liststart", "int32", 1);
ValueSet("ranklist._reg_listend", "int32", 2);
ValueSet("ranklist.record.songid", "int32", 0x39);
ValueSet("ranklist.record.diff", "int32", 0x50);
ValueSet("ranklist.record.maxpure", "int32", 0x14);
ValueSet("ranklist.record.pure", "int32", 0x18);
ValueSet("ranklist.record.far", "int32", 0x1C);
ValueSet("ranklist.record.lost", "int32", 0x20);
ValueSet("ranklist.record.trackvalue", "int32", 0x28);
ValueSet("ranklist.record.modifier", "int32", 0x54);
ValueSet("ranklist.record.time", "int32", 0x30);
ValueSet("ranklist.record.score", "int32", 0x10);
ValueSet("ranklist.record.player", "int32", 0xB0);
ValueSet("ranklist.record.player.uid", "int32", 0xC);
ValueSet("ranklist.record.player.name", "int32", 0x29);
ValueSet("inplay._libname", "string", "libcocos2dcpp.so");
do
    do
        
        local hitNote_signlocate = Memory_FindWithMask(
                                    "E0 03 01 AA E1 03 04 2A E2 03 05 2A",
                                    cocoslibbase.addr_start,
                                    cocoslibbase.addr_end);
        local hitNote_prefun = hitNote_signlocate - cocoslibbase.addr_start - 0x40;
        LogInfo(string.format("funcoffset_hitnote_pre funoff = 0x%X",hitNote_prefun));
        local asmCheck = A64.SubImm.Decode(Memory_Read_uint32(hitNote_signlocate - 0x40));
        if asmCheck.Rn ~= 31 or asmCheck.Rd ~= 31 then
            error("InPlay_HitNote: Not wanted asm.");
        end
        ValueSet("inplay._funcoffset_hitnote_pre", "int32", hitNote_prefun);
        
        if CheckAddressMask32(hitNote_prefun + cocoslibbase.addr_start + 0x48C, 0xA94003E0) then
            ValueSet("inplay._funcoffset_hitnote_post", "int32", hitNote_prefun + 0x48C);
        else
            error("InPlay_HitNote_Post: Not wanted asm.");
        end
    end
    do
        
        local missNote_signlocate = Memory_FindWithMask(
                                        "F4 03 01 AA F3 03 00 AA E0 03 14 AA",
                                        cocoslibbase.addr_start,
                                        cocoslibbase.addr_end);
        local missNote_prefun = missNote_signlocate - cocoslibbase.addr_start - 0x20;
        LogInfo(string.format("funcoffset_missnote_pre funoff = 0x%X",missNote_prefun));
        local asmCheck = A64.SubImm.Decode(Memory_Read_uint32(missNote_signlocate - 0x20));
        if asmCheck.Rn ~= 31 or asmCheck.Rd ~= 31 then
            error("InPlay_MissNote: Not wanted asm.");
        end
        ValueSet("inplay._funcoffset_missnote_pre", "int32", missNote_prefun);
        if CheckAddressMask32(missNote_prefun + cocoslibbase.addr_start + 0x19C, 0xA94003E0) then
            ValueSet("inplay._funcoffset_missnote_post", "int32", missNote_prefun + 0x19C);
        else
            error("InPlay_MissNote_Post: Not wanted asm.");
        end
    end
    local datacheck_signlocate = Memory_FindWithMask(
                                     "62 0E 48 2D 64 3E 40 BD 20 39 20 1E 61 36 40 BD",
                                     cocoslibbase.addr_start,
                                     cocoslibbase.addr_end);
	local funcoffset_datacheck = datacheck_signlocate - cocoslibbase.addr_start - 0x8C;
    LogInfo(string.format("funcoffset_datacheck funoff = 0x%X",funcoffset_datacheck));
    if CheckAddressMask32(datacheck_signlocate - 0x8C, 0x6D8003E0) then
        ValueSet("inplay._funcoffset_datacheck", "int32", funcoffset_datacheck);
    else
        error("InPlay_DataCheck: Not wanted asm.");
    end
end
ValueSet("inplay._reg_hitnote_inplaydata", "int32", 0);
ValueSet("inplay._reg_hitnote_elementdata", "int32", 1);
ValueSet("inplay._reg_hitnote_timing", "int32", 4);
ValueSet("inplay._reg_missnote_inplaydata", "int32", 0);
ValueSet("inplay._reg_missnote_elementdata", "int32", 1);
ValueSet("inplay._reg_datacheck_inplaydata", "int32", 0);
ValueSet("inplay.info", "int32", 0xB0);
ValueSet("inplay.maxnote", "int32", 0xC);
ValueSet("inplay.score", "int32", 0x14);
ValueSet("inplay.maxpure", "int32", 0x60);
ValueSet("inplay.pure", "int32", 0x64);
ValueSet("inplay.far", "int32", 0x68);
ValueSet("inplay.lost", "int32", 0x6C);
ValueSet("inplay.pure_early", "int32", 0x8C);
ValueSet("inplay.pure_late", "int32", 0x88);
ValueSet("inplay.far_early", "int32", 0x84);
ValueSet("inplay.far_late", "int32", 0x80);
ValueSet("inplay.abstime", "int32", 0xE0);
ValueSet("inplay.info.songid", "int32", 0x10);
ValueSet("inplay.info.songdiff", "int32", 0x18);
ValueSet("inplay.info.songid.ptr", "int32", 0x1);
ValueSet("inplay.info.songdiff.ptr", "int32", 0x124);
do
    ValueSet("world._libname", "string", "libcocos2dcpp.so");
    signlocate_world = Memory_FindWithMask(
                        "08 7D 0B 9B 09 FD 7F D3 08 FD 65 93 08 01 09 0B 00 05 00 11",
                        cocoslibbase.addr_start, cocoslibbase.addr_end);
    funcoff_world = signlocate_world - cocoslibbase.addr_start - 0x250;
    local find = SearchFunctionStart(signlocate_world - 0x250, 0x28);
    if find ~= nil then
        LogInfo(string.format("funcoffset_world funoff = 0x%X", find - cocoslibbase.addr_start));
        ValueSet("world._funcoffset", "int32", find - cocoslibbase.addr_start);
    else
        error("WorldStep: Unable to locate function start.");
    end
end
ValueSet("world._reg", "int32", 0);
ValueSet("world.movestep", "int32", 0x4C);
ValueSet("world.movestepnobonus", "int32", 0x7C);
ValueSet("world.playbase", "int32", 0x44);
ValueSet("world.charstepnobonus", "int32", 0x3C);
ValueSet("world.charstep", "int32", 0x78);
ValueSet("frag._libname", "string", "libcocos2dcpp.so");
do
    local signlocate = Memory_FindWithMask(
                           "08 3D 40 F9 08 15 40 B9 1F 05 00 71 6B 1E 00 54",
                           cocoslibbase.addr_start, cocoslibbase.addr_end);
    local asmBase = signlocate - 0x50;
    local cmdLibBase = asmBase - cocoslibbase.addr_start;
    local cmdLibPageBase = cmdLibBase // 0x1000 * 0x1000;
    local adrpInfo = A64.Address.Decode(Memory_Read_uint32(asmBase));
    local ldrInfo = A64.LoadRegister.Decode(Memory_Read_uint32(asmBase + 4));
	local libofftarget = cmdLibPageBase + adrpInfo.Offset + ldrInfo.Offset;
    local target = Memory_Read_uint64(cocoslibbase.addr_start + libofftarget);
	target = target - cocoslibbase.addr_start;
	ValueSet("frag.static_address", "int32", target);
	LogInfo(string.format("frag asm base = 0x%X",cmdLibBase));
	LogInfo(string.format("frag inlib lookup = 0x%X",libofftarget));
	LogInfo(string.format("frag address = 0x%X", target));
end
ValueSet("frag.ptr1", "int32", 0x78);
ValueSet("frag.frag", "int32", 0x14);
ValueSet("songselect._libname", "string", "libcocos2dcpp.so");
do
    local signlocate_songselect = Memory_FindWithMask(
                                "A8 A7 7C A9 1F 01 09 EB A1 00 00 54 0A 00 00 14",
                                cocoslibbase.addr_start, cocoslibbase.addr_end);
    local funcoff_songselected = signlocate_songselect - 0x104;
    local find = SearchFunctionStart(funcoff_songselected, 0x28);
    if find ~= nil then
        LogInfo(string.format("funcoff_songselected = 0x%X", find - cocoslibbase.addr_start));
        ValueSet("songselect._funcoffset", "int32", find - cocoslibbase.addr_start);
    else
        error("SongSelect: Unable to find function start.");
    end
end
ValueSet("songselect._reg_songid", "int32", 1);
ValueSet("songselect._reg_diff", "int32", 2);
ValueSet("sceneswitch._libname", "string", "libcocos2dcpp.so");
do
    signlocate_sceneswitch = Memory_FindWithMask("4A AE AC 72 AB CC 8D 52",
                                                cocoslibbase.addr_start,
                                                cocoslibbase.addr_end);
    funcoff_sceneswitch = signlocate_sceneswitch - cocoslibbase.addr_start - 0x24;
    local asm = A64.SubImm.Decode(Memory_Read_uint32(signlocate_sceneswitch - 0x24));
    if asm.Rd ~= 31 or asm.Rn ~= 31 then
        error("SceneSwitch: Not wanted asm.");
    end
    LogInfo(string.format("funcoff_sceneswitch = 0x%X",funcoff_sceneswitch));
    ValueSet("sceneswitch._funcoffset", "int32",funcoff_sceneswitch);
end
ValueSet("sceneswitch._reg_scenename", "int32", 1);
return 0;

