
## build Android kernel

See [this](https://source.android.com/setup/build/building-kernels) for more details.
```
mkdir android-kernel && cd android-kernel
repo init -u https://android.googlesource.com/kernel/manifest -b android-gs-raviole-5.10-android12L
repo sync

./build/build.sh (note macOS is not supported to build Android kernel)
```

## Generate basic config
```
python scripts/genConfig.py -t android --type adb --name mate9 --adb /path/to/adb
```
