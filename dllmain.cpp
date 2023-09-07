// example-c.cpp : Defines the entry point for the DLL application.
//

//#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
// Windows Header Files:

#include "pch.h"


int selfid;
int memorybrowserpluginid = -1; //initialize it to -1 to indicate failure (used by the DisablePlugin routine)
int addresslistPluginID = -1;
int debugpluginID = -1;
int ProcesswatchpluginID = -1;
int PointerReassignmentPluginID = -1;
int MainMenuPluginID = -1;

ExportedFunctions Exported;

void cleanHeader(UNICODE_STRING DllName) 
{
	HMODULE _hMod = GetModuleHandle(DllName.Buffer);
	IMAGE_DOS_HEADER   dosH{};
	IMAGE_NT_HEADERS   ntH{};
	char zerobuffer[1024] = { 0 };
	PIMAGE_DOS_HEADER  dosHeader = (PIMAGE_DOS_HEADER)_hMod;
	PIMAGE_NT_HEADERS  ntHeader = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (uint64_t)_hMod);
	DWORD dOld;
	uint64_t cleansize = (uint64_t)ntHeader - (uint64_t)dosHeader;
	VirtualProtect(dosHeader, cleansize, PAGE_EXECUTE_READWRITE, &dOld);
	memcpy(dosHeader, zerobuffer, cleansize - 1);
}
void HideModule()
{
	PPEB_LDR_DATA ldr;
	PLDR_DATA_TABLE_ENTRY Node;
	PLIST_ENTRY Head, Temp;
	PPEB peb = RtlGetCurrentPeb();
	ldr = peb->Ldr;


	// 分别将三个链表断链处理
	//1
	Head = &(ldr->InLoadOrderModuleList);    //第一项是自己的exe，windbg显示不出来
	Temp = Head->Flink;
	//printf("以下为所有模块名:\n");
	do
	{
		//CONTAINING_RECORD宏的作用就是根据结构体类型和结构体中成员变量地址和名称，则可求出该变量所在结构体的指针
		Node = (PLDR_DATA_TABLE_ENTRY)Temp;    //InLoadOrderLinks就是结构体第一个成员，不必CONTAINING_RECORD
		//printf("%ls\n", Node->BaseDllName.Buffer);    //打印所有模块名
		
		//if (!STRCMP(Node->BaseDllName.Buffer, DllName.Buffer))
		{
			Node->InLoadOrderLinks.Blink->Flink = Node->InLoadOrderLinks.Flink;
			Node->InLoadOrderLinks.Flink->Blink = Node->InLoadOrderLinks.Blink;
		}
		Temp = Temp->Flink;
	} while (Head != Temp);
	//2
	Head = &(ldr->InMemoryOrderModuleList);
	Temp = Head->Flink;
	do
	{
		//CONTAINING_RECORD宏的作用就是根据结构体类型和结构体中成员变量地址和名称，则可求出该变量所在结构体的指针
		Node = CONTAINING_RECORD(Temp, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		//if (!STRCMP(Node->BaseDllName.Buffer, DllName.Buffer))
		{
			Node->InMemoryOrderLinks.Blink->Flink = Node->InMemoryOrderLinks.Flink;
			Node->InMemoryOrderLinks.Flink->Blink = Node->InMemoryOrderLinks.Blink;
		}
		Temp = Temp->Flink;
	} while (Head != Temp);
	//3
	Head = &(ldr->InInitializationOrderModuleList);
	Temp = Head->Flink;
	do
	{
		//CONTAINING_RECORD宏的作用就是根据结构体类型和结构体中成员变量地址和名称，则可求出该变量所在结构体的指针
		Node = CONTAINING_RECORD(Temp, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
		//if (!STRCMP(Node->BaseDllName.Buffer, DllName.Buffer))
		{
			Node->InInitializationOrderLinks.Blink->Flink = Node->InInitializationOrderLinks.Flink;
			Node->InInitializationOrderLinks.Flink->Blink = Node->InInitializationOrderLinks.Blink;
		}
		Temp = Temp->Flink;
		//cleanHeader(Node->BaseDllName);
	} while (Head != Temp);
}

void __stdcall mainmenuplugin(void)
{
	Exported.ShowMessage("hide on");
	HideModule();
	return;
}

void __stdcall PointersReassigned(int reserved)
{
	//Check the "Pointer to pointer" objects and decide if you want to redirect them to your own routine, or not
	//Usefull for implementing your own read process memory and overriding user choises 
	//(e.g when they pick read physical memory and you want to focus on only one procesS)
	Exported.ShowMessage("Pointers got modified");
	return;
}

void __stdcall processWatcherEvent(ULONG processid, ULONG peprocess, BOOL Created)
{
	//Note: This is in a seperate thread. So don't use thread-unsafe (gui) functions
	char x[100];
	if (Created)
		sprintf_s(x, 100, "Processid %x (PEPROCESS: %x) has been created", processid, peprocess);
	else
		sprintf_s(x, 100, "Processid %x (PEPROCESS: %x) has been destroyed", processid, peprocess);

	MessageBoxA(0, x, "Process Watcher Plugin Example", MB_OK);
	return;
}

int __stdcall debugeventplugin(LPDEBUG_EVENT DebugEvent)
{
	//Note, because this is called from a different thread than the mainthread, the thread un-safe ShowMessage is better not used.
	MessageBoxA(0, "A debug event has happened. You could do some editing of the context here...", "Debug Event Plugin Example", MB_OK);
	return 0; //If you return 1 you will have to call ContinueDebugEvent yourself.
}

BOOL __stdcall addresslistplugin(PPLUGINTYPE0_RECORD SelectedRecord)
{
	char x[100];

	sprintf_s(x, 100, "Selected record's description=%s Address=%0.8llx", SelectedRecord->description, (UINT64)SelectedRecord->address);
	Exported.ShowMessage(x); //show it using CE's default messagebox
	return FALSE; //return TRUE if you edited anything in the record and want to apply that to the table
}

BOOL __stdcall memorybrowserplugin(UINT_PTR* disassembleraddress, UINT_PTR* selected_disassembler_address, UINT_PTR* hexviewaddress)
{
	Exported.ShowMessage("A Plugin function got executed");
	*disassembleraddress = *hexviewaddress; //make the disassembleraddress and hexviewaddress the same
	return TRUE;
}


BOOL APIENTRY DllMain(HANDLE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//MessageBox(0,"This plugin dll got loaded (This message comes from the dll)","C Plugin Example",MB_OK);
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}


BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion)
{
	pv->version = CESDK_VERSION;
	pv->pluginname = "(SDK version 4: 6.0+)"; //exact strings like this are pointers to the string in the dll, so workable
	return TRUE;
}

int lua_pluginExample(lua_State* L) //make sure this is cdecl
{
	//Exported.ShowMessage("Called from lua");
	//lua_pushinteger(L, 123);
	return 1;
}


BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid)
{
	ADDRESSLISTPLUGIN_INIT init0;
	MEMORYVIEWPLUGIN_INIT init1;
	DEBUGEVENTPLUGIN_INIT init2;
	PROCESSWATCHERPLUGIN_INIT init3;
	POINTERREASSIGNMENTPLUGIN_INIT init4;
	MAINMENUPLUGIN_INIT init5;

	selfid = pluginid;

	//copy the EF list to Exported
	Exported = *ef; //Exported is defined in the .h
	if (Exported.sizeofExportedFunctions != sizeof(Exported))
		return FALSE;

	////rightclick on address plugin
	//init0.name = "Sample plugin: Addresslist";
	//init0.callbackroutine = addresslistplugin;
	//addresslistPluginID = Exported.RegisterFunction(pluginid, ptAddressList, &init0); //adds a plugin menu item to the memory view
	//if (addresslistPluginID == -1)
	//{
	//	Exported.ShowMessage("Failure to register the addresslist plugin");
	//	return FALSE;
	//}

	////memory browser plugin menu:
	//init1.name = "Sample plugin: Memoryview";
	//init1.callbackroutine = memorybrowserplugin;
	//init1.shortcut = "Ctrl+Q";
	//memorybrowserpluginid = Exported.RegisterFunction(pluginid, ptMemoryView, &init1); //adds a plugin menu item to the memory view
	//if (memorybrowserpluginid == -1)
	//{
	//	Exported.ShowMessage("Failure to register the memoryview plugin");
	//	return FALSE;
	//}

	////On Debug event plugin	
	//init2.callbackroutine = debugeventplugin;
	//debugpluginID = Exported.RegisterFunction(pluginid, ptOnDebugEvent, &init2); //adds a plugin menu item to the memory view
	//if (debugpluginID == -1)
	//{
	//	Exported.ShowMessage("Failure to register the ondebugevent plugin");
	//	return FALSE;
	//}

	////Processwatcher event (process creation/destruction)
	//init3.callbackroutine = processWatcherEvent;
	//ProcesswatchpluginID = Exported.RegisterFunction(pluginid, ptProcesswatcherEvent, &init3); //adds a plugin menu item to the memory view
	//if (ProcesswatchpluginID == -1)
	//{
	//	Exported.ShowMessage("Failure to register the processwatcherevent plugin");
	//	return FALSE;
	//}

	////Pointer reassignment event
	//init4.callbackroutine = PointersReassigned;
	//PointerReassignmentPluginID = Exported.RegisterFunction(pluginid, ptFunctionPointerchange, &init4); //adds a plugin menu item to the memory view
	//if (PointerReassignmentPluginID == -1)
	//{
	//	Exported.ShowMessage("Failure to register the pointer reassignment plugin");
	//	return FALSE;
	//}

	//Main menu plugin

	init5.name = "hide on";
	init5.callbackroutine = mainmenuplugin;
	init5.shortcut = "Ctrl+R";
	MainMenuPluginID = Exported.RegisterFunction(pluginid, ptMainMenu, &init5); //adds a plugin menu item to the memory view
	if (MainMenuPluginID == -1)
	{
		Exported.ShowMessage("Failure to register the main menu plugin");
		return FALSE;
	}

	lua_State* lua_state = ef->GetLuaState();
	//HideModule();
	lua_register(lua_state, "pluginExample", lua_pluginExample);
	//Exported.ShowMessage("The \"lulusys_hide\" plugin got enabled");
	return TRUE;
}


BOOL __stdcall CEPlugin_DisablePlugin(void)
{
	//clean up memory you might have allocated
	//MessageBoxA(0, "请重启lulusys", "lulusys_hide plugin", MB_OK);
	return TRUE;
}

