$ lldb -c /cores/core.60372 vscrypt
(lldb) target create "vscrypt" --core "/cores/core.60372"
Traceback (most recent call last):
  File "<input>", line 1, in <module>
  File "/usr/local/Cellar/python@2/2.7.15_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/copy.py", line 52, in <module>
    import weakref
  File "/usr/local/Cellar/python@2/2.7.15_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/weakref.py", line 14, in <module>
    from _weakref import (
ImportError: cannot import name _remove_dead_weakref
Core file '/cores/core.60372' (x86_64) was loaded.
(lldb) bt
* thread #1, stop reason = signal SIGSTOP
  * frame #0: 0x00007fff77d88b66 libsystem_kernel.dylib`__pthread_kill + 10
    frame #1: 0x00007fff77f53080 libsystem_pthread.dylib`pthread_kill + 333
    frame #2: 0x00007fff77ce41ae libsystem_c.dylib`abort + 127
    frame #3: 0x00007fff77ce4321 libsystem_c.dylib`abort_report_np + 177
    frame #4: 0x00007fff77d08bf5 libsystem_c.dylib`__chk_fail + 48
    frame #5: 0x00007fff77d08bc5 libsystem_c.dylib`__chk_fail_overflow + 16
    frame #6: 0x00007fff77d090eb libsystem_c.dylib`__sprintf_chk + 204
    frame #7: 0x0000000100498416 vscrypt`main at main.c:100 [opt]
    frame #8: 0x0000000100498053 vscrypt`main(argc=7, argv=0x00007ffeef7684f0) at main.c:153 [opt]
    frame #9: 0x00007fff77c38015 libdyld.dylib`start + 1
(lldb)


Linux

	docker run -it --name linuxdevbox -v `pwd`:/vsencryption alpine /bin/sh
	apk add alpine-sdk

