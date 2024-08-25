#[
  Basic heap encryption example in Nim. Compile like `nim c -d:mingw -o:./bin/ --threads:on --mm:orc -d:release .\heapEnc.nim`
  UPDATE: as of nim 2.0;
    - Using the `rollXor` proc nested in the heapsleep proc resulted in the compiler creating a clousure which uses the heap.
    - We also now need to use -mm:refc or -mm:markAndSweep since the Arc/orc models both now use shared heaps across all nim-threads
  -nbaertsch
]#
import winim/lean
import winim/inc/tlhelp32
import strformat

let keyBuf: array[16, byte] = [byte 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF ]

proc rollXor*(pkey: array[16, byte], p: ptr UncheckedArray[byte], cb: int) =
    for i in 0..cb-1:
        p[i] = p[i] xor pkey[(i mod (16))]

# Encrypts all non busy heap blocks and calls SmartEkko()
proc heapEncSleep(ms: DWORD, keyBuf: ptr array[16, byte]) {.stdcall.} =
    var numHeaps = GetProcessHeaps(0,NULL)
    var heapHandlesOnHeap = newSeq[HANDLE](numHeaps)
    GetProcessHeaps(numHeaps, (PHANDLE)(addr heapHandlesOnHeap[0]))


    var hHeap: HANDLE = HeapCreate(0,0,0) # 'Safe' heap needs to be created after calling GetProcessHeaps so we don't xor our own data
    defer: HeapDestroy(hHeap)
    
    var pHeaps: ptr UncheckedArray[HANDLE] = cast[ptr UncheckedArray[HANDLE]](HeapAlloc(hHeap, 0, (sizeof(HANDLE) * numHeaps).SIZE_T))
    copyMem(pHeaps, addr heapHandlesOnHeap[0], sizeof(HANDLE) * numHeaps)
    zeroMem(addr heapHandlesOnHeap, sizeof(heapHandlesOnHeap))

    var pHeapEntry: ptr PROCESS_HEAP_ENTRY = cast[ptr PROCESS_HEAP_ENTRY](HeapAlloc(hHeap, 0, (sizeof(PROCESS_HEAP_ENTRY)).SIZE_T))

    # Heap xor
    for i in DWORD(0) .. numHeaps-1:
        #if (pHeaps[i] == GetProcessHeap()): continue # Skip main process heap
        #echo "xoring heap ", i, " of ", numHeaps-1
        SecureZeroMemory(pHeapEntry, sizeof(PROCESS_HEAP_ENTRY))
        while HeapWalk(pHeaps[i], pHeapEntry).bool: # walking heap entries
            if (pHeapEntry[].wFlags and PROCESS_HEAP_ENTRY_BUSY) != 0: # only allocated blocks
                for i in 0..pHeapEntry[].cbData.int-1:
                    cast[ptr UncheckedArray[byte]](pHeapEntry[].lpData)[i] = cast[ptr UncheckedArray[byte]](pHeapEntry[].lpData)[i] xor keyBuf[][(i mod (16))]

    Sleep(ms)

    # Heap xor
    for i in DWORD(0) .. numHeaps-1:
        #if (pHeaps[i] == GetProcessHeap()): continue # Skip main process heap
        SecureZeroMemory(pHeapEntry, sizeof(PROCESS_HEAP_ENTRY))
        while HeapWalk(pHeaps[i], pHeapEntry).bool: # walking heap entries
            if (pHeapEntry[].wFlags and PROCESS_HEAP_ENTRY_BUSY) != 0: # only allocated blocks
                for i in 0..pHeapEntry[].cbData.int-1:
                        cast[ptr UncheckedArray[byte]](pHeapEntry[].lpData)[i] = cast[ptr UncheckedArray[byte]](pHeapEntry[].lpData)[i] xor keyBuf[][(i mod (16))]

proc DoSuspendThreads*(targetProcessId: DWORD, targetThreadId: DWORD) = 
    # Take a module snapshot and start walking through it
    var hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    var threadEntry: THREADENTRY32
    threadEntry.dwSize = sizeof(THREADENTRY32).DWORD
    var contThreadSnapWalk = Thread32First(hThreadSnap, &threadEntry)

    # ThreadSnapWalk
    while contThreadSnapWalk:
        if (threadEntry.dwSize >= (4*sizeof(DWORD))):
            #if defined DEBUG: echo &"Found thread\n\tPID: {threadEntry.th32OwnerProcessID.int.toHex()}\tTID: {threadEntry.th32ThreadID.int.toHex()}"
            if (threadEntry.th32OwnerProcessID == targetProcessId) and (threadEntry.th32ThreadID != targetThreadId):
                var hThread: HANDLE = OpenThread(THREAD_SUSPEND_RESUME, false, threadEntry.th32ThreadID)
                if hThread != 0:
                    if defined DEBUG: echo &"Suspending thread {(threadEntry.th32ThreadID).int}"
                    SuspendThread(hThread)
                    CloseHandle(hThread)

        # increment thread entry
        threadEntry.dwSize = DWORD(sizeof(THREADENTRY32))
        contThreadSnapWalk = Thread32Next(hThreadSnap, &threadEntry)

proc DoResumeThreads*(targetProcessId: DWORD, targetThreadId: DWORD) = 
    # Take a module snapshot and start walking through it
    var hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    var threadEntry: THREADENTRY32
    threadEntry.dwSize = sizeof(THREADENTRY32).DWORD
    var contThreadSnapWalk = Thread32First(hThreadSnap, &threadEntry)

    # ThreadSnapWalk
    while contThreadSnapWalk:
        if (threadEntry.dwSize >= (4*sizeof(DWORD))):
            #if defined DEBUG: echo &"Found thread\n\tPID: {threadEntry.th32OwnerProcessID.int.toHex()}\tTID: {threadEntry.th32ThreadID.int.toHex()}"
            if (threadEntry.th32OwnerProcessID == targetProcessId) and (threadEntry.th32ThreadID != targetThreadId):
                var hThread: HANDLE = OpenThread(THREAD_SUSPEND_RESUME, false, threadEntry.th32ThreadID)
                if hThread != 0:
                    if defined DEBUG: echo &"Resuming thread {(threadEntry.th32ThreadID).int}"
                    ResumeThread(hThread)
                    CloseHandle(hThread)

        # increment thread entry
        threadEntry.dwSize = DWORD(sizeof(THREADENTRY32))
        contThreadSnapWalk = Thread32Next(hThreadSnap, &threadEntry)

when isMainModule:
    #enableHook(heapEncSleep)
    while true:
        echo "sleeping for 3 on key ->"
        discard stdin.readline
        DoSuspendThreads(GetCurrentProcessId(), GetCurrentThreadId())
        heapEncSleep(3 * 1000, keyBuf.addr)
        DoResumeThreads(GetCurrentProcessId(), GetCurrentThreadId())
