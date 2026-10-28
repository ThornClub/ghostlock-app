# gate-apk failure

sha: 9c6aa523b81f3a9d56f571c6cd797465d742f855

## apk candidates
```
./build/app/outputs/apk/debug/GhostLock-v1.2(626)-arm64-v8a-debug.apk
```
## outputs tree
```
build/app/outputs:
apk
logs

build/app/outputs/apk:
debug

build/app/outputs/apk/debug:
GhostLock-v1.2(626)-arm64-v8a-debug.apk
output-metadata.json

build/app/outputs/logs:
manifest-merger-debug-report.txt
```
## gradle output tail
```
[1m[92m   Compiling[0m zip v8.6.0
[1m[92m   Compiling[0m sha2 v0.11.0
[1m[92m   Compiling[0m xz2 v0.1.7
[1m[92m   Compiling[0m clap v4.6.7
[1m[92m   Compiling[0m zstd v0.13.3
[1m[92m   Compiling[0m memmap2 v0.9.11
[1m[92m   Compiling[0m lz4_flex v0.14.0
[1m[92m   Compiling[0m hex v0.4.3
[1m[92m   Compiling[0m yaxpeax-arm v0.5.0
[1m[92m   Compiling[0m flate2 v1.1.10
[1m[92m   Compiling[0m ghostlock-extract v0.1.0 (/home/runner/work/ghostlock-app/ghostlock-app/tools/extract_rs)

> Task :app:mergeProjectDexDebug

> Task :buildGhostlockExtract
[1m[92m    Finished[0m `release` profile [optimized] target(s) in 3m 46s

> Task :prepareGhostlockExtractJniLibs
> Task :app:mergeDebugJniLibFolders
> Task :app:mergeDebugNativeLibs

> Task :app:stripDebugDebugSymbols
Unable to strip the following libraries, packaging them as they are: libextract.so, libghostlock.so, libn5fanout.so, libn5rotate.so. Run with --info option to learn more.

> Task :app:packageDebug
> Task :app:assembleDebug
> Task :app:createDebugApkListingFileRedirect
gradle/actions: Writing build results to /home/runner/work/_temp/.gradle-actions/build-results/__run_3-1793179127221.json

[Incubating] Problems report is available at: file:///home/runner/work/ghostlock-app/ghostlock-app/build/reports/problems/problems-report.html

Deprecated Gradle features were used in this build, making it incompatible with Gradle 10.

You can use '--warning-mode all' to show the individual deprecation warnings and determine if they come from your own scripts or plugins.

For more on this, please refer to https://docs.gradle.org/9.7.1/userguide/command_line_interface.html#sec:command_line_warnings in the Gradle documentation.

BUILD SUCCESSFUL in 4m 7s
46 actionable tasks: 43 executed, 3 from cache
Configuration cache entry stored.
```
