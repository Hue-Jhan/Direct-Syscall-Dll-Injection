
.data
extern h_NtOpenProcessSSN:DWORD
extern h_NtAllocateVirtualMemorySSN:DWORD
extern h_NtWriteVirtualMemorySSN:DWORD
extern h_NtProtectVirtualMemorySSN:DWORD
extern h_NtCreateThreadExSSN:DWORD
extern h_NtWaitForSingleObjectSSN:DWORD
extern h_NtFreeVirtualMemorySSN:DWORD
extern h_NtCloseSSN:DWORD

.code
NtOpenProcess proc 
		mov r10, rcx
		mov eax, h_NtOpenProcessSSN       
		syscall                         
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc    
		mov r10, rcx
		mov eax, h_NtAllocateVirtualMemorySSN      
		syscall                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc 
		mov r10, rcx
		mov eax, h_NtWriteVirtualMemorySSN      
		syscall                        
		ret                             
NtWriteVirtualMemory endp 

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, h_NtProtectVirtualMemorySSN       
		syscall
		ret                             
NtProtectVirtualMemory endp

NtCreateThreadEx proc 
		mov r10, rcx
		mov eax, h_NtCreateThreadExSSN      
		syscall                        
		ret                             
NtCreateThreadEx endp 

NtWaitForSingleObject proc 
		mov r10, rcx
		mov eax, h_NtWaitForSingleObjectSSN      
		syscall                        
		ret                             
NtWaitForSingleObject endp 

NtFreeVirtualMemory proc
		mov r10, rcx
		mov eax, h_NtFreeVirtualMemorySSN      
		syscall
		ret                             
NtFreeVirtualMemory endp

NtClose proc 
		mov r10, rcx
		mov eax, h_NtCloseSSN      
		syscall                        
		ret                             
NtClose endp 
end
