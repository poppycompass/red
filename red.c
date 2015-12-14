#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include "hookapi.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static plugin_interface_t red_interface;
static DECAF_Handle processbegin_handle      = DECAF_NULL_HANDLE;
static DECAF_Handle blockbegin_handle        = DECAF_NULL_HANDLE;
static DECAF_Handle insnbegin_handle         = DECAF_NULL_HANDLE;
static DECAF_Handle insnend_handle           = DECAF_NULL_HANDLE;

// hook api
static DECAF_Handle isdebuggerpresent_handle = DECAF_NULL_HANDLE;
static DECAF_Handle sleep_handle             = DECAF_NULL_HANDLE;
static DECAF_Handle gettickcount_handle      = DECAF_NULL_HANDLE;
static DECAF_Handle getsysteminfo_handle     = DECAF_NULL_HANDLE;

char targetname[512];
uint32_t target_cr3;

typedef struct {
    uint32_t call_stack[1]; //return address only -> VOID
    DECAF_Handle hook_handle;
} IsDebuggerPresent_hook_context_t;

typedef struct {
    uint32_t call_stack[2]; // return address and parameters ([0]: ret addr, [1]: time)
    DECAF_Handle hook_handle;
} Sleep_hook_context_t;

typedef struct {
    uint32_t call_stack[1]; // return address only -> VOID
    DECAF_Handle hook_handle;
} GetTickCount_hook_context_t;

typedef struct {
    uint32_t call_stack[10];  // return address and parameters
    DECAF_Handle hook_handle;
} GetSystemInfo_hook_context_t;
/* typedef struct _SYSTEM_INFO { // sinf 
   call_stack[0]:    union {
   DWORD  dwOemId; 
   struct { 
   WORD wProcessorArchitecture; 
   WORD wReserved; 
   }; 
   }; 
   call_stack[1]:   DWORD  dwPageSize; 
   call_stack[2]:   LPVOID lpMinimumApplicationAddress; 
   call_stack[3]:   LPVOID lpMaximumApplicationAddress; 
   call_stack[4]:   DWORD  dwActiveProcessorMask; 
   call_stack[5]:   DWORD  dwNumberOfProcessors; 
   call_stack[6]:   DWORD  dwProcessorType; 
   call_stack[7]:   DWORD  dwAllocationGranularity; 
   call_stack[8]_low:    WORD  wProcessorLevel; 
   call_stack[8]_high:   WORD  wProcessorRevision; 
   } SYSTEM_INFO;
   */

// bypass level3
static void level3(int line_num)
{
    uint32_t NumberOfProcessors = 0;
    uint32_t base = 0, peb_addr = 0, peb = 0;
    base = cpu_single_env->segs[R_FS].base;
    peb_addr = base + 0x30;
    DECAF_read_mem(NULL, peb_addr, 4, &peb);
    DECAF_read_mem(NULL, peb+0x64, 4, &NumberOfProcessors);
    //DECAF_printf("FS(TEB): 0x%08x, peb_addr: 0x%08x, peb: 0x%08x\n", base, peb_addr, peb);

    NumberOfProcessors = 0x2;  // change NumOfProcessors
    DECAF_write_mem(NULL, peb+0x64, 4, &NumberOfProcessors);  // write back to memory
}
// level3 end

/*
 * BOOL IsDebuggerPresent(VOID);
 */

static void IsDebuggerPresent_ret(void *param)
{
    // DECAF_printf("IsDebuggerPresent exit\n");
    IsDebuggerPresent_hook_context_t *ctx = (IsDebuggerPresent_hook_context_t *)param;
    hookapi_remove_hook(ctx->hook_handle);
    cpu_single_env->regs[R_EAX] = 0;    // IsDebuggerPresent always return 0
    //DECAF_printf("EIP = %08x, EAX = %d\n", cpu_single_env->eip, cpu_single_env->regs[R_EAX]);
    free(ctx);
}

static void IsDebuggerPresent_call(void *opaque)
{
    // DECAF_printf("IsDebuggerPresent entry\n");
    IsDebuggerPresent_hook_context_t *ctx = (IsDebuggerPresent_hook_context_t*)malloc(sizeof(IsDebuggerPresent_hook_context_t));
    if(!ctx) return;
    DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4, ctx->call_stack);
    ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0], IsDebuggerPresent_ret, ctx, sizeof(*ctx));
}

/* IsDebuggerPresent end */

/*
 * BOOL Sleep(DWORD dwMilliseconds);
 */

static void Sleep_ret(void *param)
{
    // DECAF_printf("Sleep exit\n");
    Sleep_hook_context_t *ctx = (Sleep_hook_context_t *)param;
    hookapi_remove_hook(ctx->hook_handle);
    free(ctx);
}

static void Sleep_call(void *opaque)
{
    // DECAF_printf("Sleep entry\n");
    Sleep_hook_context_t *ctx = (Sleep_hook_context_t*)malloc(sizeof(Sleep_hook_context_t));
    if(!ctx) return;

    // bypass Sleep
    // 2*4: call_stack size
    DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);
    ctx->call_stack[1] = 1; // argument is always 1
    DECAF_write_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);
    // bypass Sleep end

    ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0], Sleep_ret, ctx, sizeof(*ctx));
}
/* Sleep end */

/*
 * DWORD GetTickCount(VOID)
 */

static void GetTickCount_ret(void *param)
{
    static int flag = 0;    // level2
    // DECAF_printf("GetTickCount exit\n");
    GetTickCount_hook_context_t *ctx = (GetTickCount_hook_context_t *)param;
    hookapi_remove_hook(ctx->hook_handle);
    if (!flag) {                                // ture is only first call
        cpu_single_env->regs[R_EAX] = 0;    // return 0
        flag = 1
    } else {
        flag = 0;
    }
    // DECAF_printf("EIP = %08x, EAX = %d\n", cpu_single_env->eip, cpu_single_env->regs[R_EAX]);
    free(ctx);
}

static void GetTickCount_call(void *opaque)
{
    // DECAF_printf("GetTickCount entry\n");
    GetTickCount_hook_context_t *ctx = (GetTickCount_hook_context_t*)malloc(sizeof(GetTickCount_hook_context_t));
    if(!ctx) return;
    DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4, ctx->call_stack);
    ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0], GetTickCount_ret, ctx, sizeof(*ctx));
}
/* GetTickCount end */

/*
 * VOID GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
 */

static void GetSystemInfo_ret(void *param)
{
    // DECAF_printf("GetSystemInfo exit\n");
    GetSystemInfo_hook_context_t *ctx = (GetSystemInfo_hook_context_t *)param;
    hookapi_remove_hook(ctx->hook_handle);
    DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 10*4, ctx->call_stack);
    ctx->call_stack[5] = 0x2;  // SYSTEM_INFO.dwNumberOfProcessors is 0x2
    DECAF_write_mem(NULL, cpu_single_env->regs[R_ESP], 10*4, ctx->call_stack);  // write back to memory
    // DECAF_printf("EIP = %08x, EAX = %d\n", cpu_single_env->eip, cpu_single_env->regs[R_EAX]);
}

static void GetSystemInfo_call(void *opaque)
{
    // DECAF_printf("GetSystemInfo entry\n");
    GetSystemInfo_hook_context_t *ctx = (GetSystemInfo_hook_context_t*)malloc(sizeof(GetSystemInfo_hook_context_t));
    if(!ctx) return;
    DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4, ctx->call_stack);
    ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0], GetSystemInfo_ret, ctx, sizeof(*ctx));
}

/* GetSystemInfo end */

/* share function */
static void red_block_begin_callback(DECAF_Callback_Params* params)
{
    if(params->bb.env->cr[3] == target_cr3)
    {
        target_ulong eip = params->bb.env->eip; 
        target_ulong eax = params->bb.env->regs[R_EAX]; 
    }
}

// level4
static uint32_t save_peb = 0;
static uint32_t save_val[2] = {0, 0};
static uint32_t save_base = 0;
static void red_insn_begin_callback(DECAF_Callback_Params* params)
{
    // detect cmpxchg8b and replace fs:[0x1000]
    uint32_t cur_insn = 0,
             cmpxchg8b = 0x00c70f64, // opcode of 'cmpxchg8b: 0x640fc7 ->(fix endian) 0x00c70f64 
             base, peb_addr, tmp_addr;
    DECAF_read_mem(NULL, cpu_single_env->eip, 3, &cur_insn);
    if (cur_insn == cmpxchg8b) {    // catch cmpxchg8b
        base = cpu_single_env->segs[R_FS].base;
        DECAF_read_mem(NULL, base+0x30, 4, &save_peb);  // get peb
        if (base > save_peb) { // peb is rear base
            DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 8, save_val);
            /*                  DECAF_printf("FS(TEB): 0x%08x, peb: 0x%08x\n", base, save_peb); */
            /*                  DECAF_printf("edx:eax %08x:%08x, ecx:ebx %08x:%08x\n", cpu_single_env->regs[R_EDX], cpu_single_env->regs[R_EAX], cpu_single_env->regs[R_ECX], cpu_single_env->regs[R_EBX]); */
            save_base = base;
            cpu_single_env->segs[R_FS].base = cpu_single_env->regs[R_ESP]-0x1000;  // fs = ESP - 0x1000
        }
    }
}

static void red_insn_end_callback(DECAF_Callback_Params* params)
{
    return;
}
// level4 end

static void red_loadmainmodule_callback(VMI_Callback_Params* params)
{
    // targetname = "blue.exe"
    {
        DECAF_printf("Process %s you spcecified starts \n", params->cp.name);
        target_cr3 = params->cp.cr3;
        isdebuggerpresent_handle = hookapi_hook_function_byname("kernel32.dll", "IsDebuggerPresent", 1, target_cr3, IsDebuggerPresent_call, NULL, 0);
        sleep_handle = hookapi_hook_function_byname("kernel32.dll", "Sleep", 1, target_cr3, Sleep_call, NULL, 0);
        gettickcount_handle = hookapi_hook_function_byname("kernel32.dll", "GetTickCount", 1, target_cr3, GetTickCount_call, NULL, 0);
        getsysteminfo_handle = hookapi_hook_function_byname("kernel32.dll", "GetSystemInfo", 1, target_cr3, GetSystemInfo_call, NULL, 0);
        blockbegin_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, &red_block_begin_callback, NULL);
        insnbegin_handle = DECAF_register_callback(DECAF_INSN_BEGIN_CB, &red_insn_begin_callback, NULL);    // level4
        insnend_handle = DECAF_register_callback(DECAF_INSN_END_CB, &red_insn_end_callback, NULL);  // level4
        level3(__LINE__);   // replace NumberOfProcessors
    }
}

void do_monitor_proc(Monitor* mon, const QDict* qdict)
{
    // targetname = "blue.exe"
    if ((qdict != NULL) && (qdict_haskey(qdict, "procname")))
        strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
    targetname[511] = '\0';
    DECAF_printf("red: Ready to track %s\n", targetname);
}

static int red_init(void)
{
    DECAF_printf("Hello, World!\n");
    processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &red_loadmainmodule_callback, NULL);
    if (processbegin_handle == DECAF_NULL_HANDLE)
        DECAF_printf("Could not register for the create or remove proc events\n");  
    return 0;
}

static void red_cleanup(void)
{
    DECAF_printf("Bye, World\n");
    if (processbegin_handle != DECAF_NULL_HANDLE)
    {
        VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);  
        processbegin_handle = DECAF_NULL_HANDLE;
    }
    if (blockbegin_handle != DECAF_NULL_HANDLE)
    {
        DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, blockbegin_handle);
        blockbegin_handle = DECAF_NULL_HANDLE;
    }
    // level4
    if (insnbegin_handle != DECAF_NULL_HANDLE)
    {
        DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, insnbegin_handle);
        insnbegin_handle = DECAF_NULL_HANDLE;
    }
    if (insnend_handle != DECAF_NULL_HANDLE)
    {
        DECAF_unregister_callback(DECAF_INSN_END_CB, insnend_handle);
        insnend_handle = DECAF_NULL_HANDLE;
    }
    // level4 end
}

/* share function end */

static mon_cmd_t red_term_cmds[] = 
{
#include "plugin_cmds.h"
    {NULL, NULL, },
};

plugin_interface_t* init_plugin(void)
{
    red_interface.mon_cmds = red_term_cmds;
    red_interface.plugin_cleanup = &red_cleanup;
    red_init();
    return (&red_interface);
}
