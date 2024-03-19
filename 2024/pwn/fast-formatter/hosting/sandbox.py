import ast

safe_globals = {'__builtins__': {i.__name__: i for i in [
    abs, all, any, ascii, bin, bool, bytes, callable, chr, complex, dict, divmod, 
    enumerate, float, frozenset, hash, hex, input, id, int, isinstance, issubclass, iter, len, 
    list, map, max, min, next, object, oct, ord, pow, print, property, range, repr, reversed, 
    round, set, slice, sorted, str, sum, tuple, type, zip, BaseException, Exception
]}}
def check_source(source_code):
    tree = compile(source_code, "<inline>", 'exec', flags=ast.PyCF_ONLY_AST)
    
    for x in ast.walk(tree):
        match type(x):
            case (ast.Import|ast.ImportFrom|ast.Delete|ast.Match|ast.ClassDef|ast.AsyncFunctionDef|ast.AsyncFor|ast.AsyncWith|ast.Await|ast.Yield|ast.Try|ast.ExceptHandler):
                return False
            case ast.Attribute:
                if any(x.attr.startswith(i) for i in ['_', 'gi_', 'cr_', 'f_', 'format']):
                    return False
            case ast.Name:
                if x.id.startswith("_"):
                    return False
    return True
