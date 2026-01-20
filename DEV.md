Build flags:
* `-DNONROOT_OK` allows running as non-root
* `-DDOC_LOC=<dir>` changes the directory of the documents
* `-D_DISABLE_FIX_ISSUE_NO2` disables the fix for Issue #2
* `-D_DISABLE_FILE_PROTECTIONS` disables explicit file protections (NOT RECOMMENDED). Also disables protection-based filtering.
* `-D_DISABLE_FILE_PROTECTION_FILTERING` disables only filtering files based on explicit protections. (NOT RECOMMENDED)
* `-DEXPER_ENABLE_ALL_FEAT` enables all experimental features

For a debug build: `./build.sh -DEXPER_ENABLE_ALL_FEAT -O0 -g -fsanitize=undefined`

For a production build: `./build.sh -Os -fstack-protector-all -D_FORTIFY_SOURCE=1 -fPIE -pie -Wl,-z,relro`
