# diStormX
The ultimate hooking library  
Features:  
* Supports both x86/x64
* Simple APIs and batch hooks
* Low memory foot print, will re-use trampoline pages as much as possible
* RWX sensitive, will temporarily enable RWX and then revert to RX when writing trampolines
* Uses a private heap
* Uses an OS abstraction layer - easy to add support for other OSs
* Currently supports only Windows

This library is licensed under BSD.
