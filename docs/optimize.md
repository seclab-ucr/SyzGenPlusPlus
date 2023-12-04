
# Optimization

Symbolic execution is notorious for its path explosion. To alleviate this problem, we applied one error-code-based heuristic to prune undesired paths. This is because returning error code usually indicates an error path deviating from the desired ones and thus there is no need to further execute them, based on which we eliminate paths via two approach as follows:

## Detect Error Code on Return
When executing return instructions, we check the register holding the return value and halt the path if it is in the range of error codes. Note that it does not necessarily mean that it is an error code. I have seen cases where some functions do not return anything but the particular return register happens to contain an error-code-like value. Thus, we also make sure the return value is used in the call site to reduce false positives.

Some functions may use different error code (e.g., False or 0). User can also specifiy how to detect error codes for particular functions by modifying the config file as follows:

```
"error_code": [
    {
        "addr": "0x11a16",
        "module": "com.apple.iokit.IOBluetoothFamily",
        "func": "lambda x: x&0xff == 0"
    }
]
```

## Detect Blocks Leading to Error Path
To proactively detect error paths even before they reach the return instructions, we also perform intra-procedure static analysis to find blocks that definitely leads to returning error code.

## Manual Config
Users can also provide a list of block addresses where SE should stop in the config file:

```
"dead": {
    "com.apple.iokit.IOBluetoothFamily": ["0x122b3"],
    "kernel": []
}
```

Note that each address is an relative offset in the binary and accompanied by its module name. For macOS, we use drivers' identifiers as the module name and the core kernel is indicated by `kernel`.

It is common to have complex functions that do not affect the execution of other parts and hence can be modeled by a dummy model (e.g., directly returning a zero). To the end, user can provide a list of function addresses to skip those functions. We currently provide two dummy models: returing with zero and returning with one. You can modify the config file to specify them.

```
"funcWithZero": {
    "com.apple.iokit.IOBluetoothFamily": ["0x57d8"]
},
"funcWithOne": {
}
```
