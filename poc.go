package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main(){

	apiName := "NtReadVirtualMemory"
	nt := syscall.NewLazyDLL("ntdll").NewProc(apiName).Addr()
	fmt.Printf("API name:%s\n",apiName)
	fmt.Printf("API Addr:0x%x\n",nt)

	for i := uintptr(0);i<21;i++{
		fmt.Printf("\\x%x", *(*byte)(unsafe.Pointer(nt+i)))
	}


	fmt.Println("\nbefore replace:")
	fmt.Printf("\\x0%x", *(*byte)(unsafe.Pointer(nt+18)))
	fmt.Printf("\\x0%x", *(*byte)(unsafe.Pointer(nt+19)))
	fmt.Printf("\\x%x\n\n", *(*byte)(unsafe.Pointer(nt+20)))

	replace:= []byte{0x90,0x90}
	raw:= []byte{0x0f,0x05}

	if *(*byte)(unsafe.Pointer(nt+18)) == 0x0f &&
		*(*byte)(unsafe.Pointer(nt+19)) == 0x05 &&
		*(*byte)(unsafe.Pointer(nt+20)) == 0xc3{
		windows.WriteProcessMemory(0xffffffffffffffff,nt+18,(*byte)(unsafe.Pointer(&replace[0])),2,nil)
	}

	fmt.Println("after replace:")
	fmt.Printf("\\x%x", *(*byte)(unsafe.Pointer(nt+18)))
	fmt.Printf("\\x%x", *(*byte)(unsafe.Pointer(nt+19)))
	fmt.Printf("\\x%x\n\n", *(*byte)(unsafe.Pointer(nt+20)))

	sysid,_,_ := syscall.Syscall(nt,0,0,0,0)
	fmt.Printf("sysid: %d\n\n",sysid)

	windows.WriteProcessMemory(0xffffffffffffffff,nt+18,(*byte)(unsafe.Pointer(&raw[0])),2,nil)

	fmt.Println("recover:")
	fmt.Printf("\\x0%x", *(*byte)(unsafe.Pointer(nt+18)))
	fmt.Printf("\\x0%x", *(*byte)(unsafe.Pointer(nt+19)))
	fmt.Printf("\\x%x\n\n", *(*byte)(unsafe.Pointer(nt+20)))


}

