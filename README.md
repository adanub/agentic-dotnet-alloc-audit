# agentic-dotnet-alloc-audit

A static managed-allocation auditor for .NET / IL2CPP / Mono assemblies. It disassembles
assemblies with [ilspycmd](https://github.com/icsharpcode/ILSpy) and scans the IL for
allocation patterns, attributing each to its containing method and optionally flagging the
ones inside caller-supplied "hot path" methods.

It is **project-agnostic**: which assemblies to scan and what counts as a "hot path" are
*inputs*, not baked in. Project-specific usage (assembly lists, hot-path regexes, known
landmines, the profiler workflow) belongs in a thin project-side wrapper or skill that
supplies a config file and the verification workflow.

## ⚠️ This is a candidate finder, not a GC oracle

Two hard limits — internalise them or the output will mislead:

1. **It finds allocation _sites_, not _hotness_.** A `newobj` in `Awake`, a `.cctor`, or a
   one-time event subscription is almost always harmless. Use `--hot-path` to pre-filter to
   methods that actually run per frame, and **still confirm in a profiler**.
2. **It is blind to allocations _inside_ the BCL / engine.** The parameterless
   `Array.Sort(T[])` overload, for instance, can allocate inside Mono with **no `newobj` in
   your IL** — this scanner will never see it. Only a runtime profiler will.

Always treat the output as a **shortlist to verify in the profiler** (in Unity: deep profile
+ allocation callstacks), never as proof that something does or doesn't allocate.

## Requirements

- Python 3.8+
- .NET SDK (`dotnet` on `PATH`) — used once to bootstrap `ilspycmd`.

`ilspycmd` is resolved in this order: `--ilspycmd <path>` → local `.tools/` (gitignored) →
`PATH` → auto-install into `.tools/` via `dotnet tool install`. The first run installs it.

## Usage

```bash
# Delegate allocations in one assembly, flag per-frame methods as hot:
python alloc_audit.py \
  --assembly path/to/Assembly-CSharp.dll \
  --detectors delegate \
  --hot-path "Update|LateUpdate|FixedUpdate"

# All detectors across a directory, only hot-path hits, as JSON:
python alloc_audit.py \
  --assembly-dir path/to/ScriptAssemblies --pattern "MyGame*.dll" \
  --detectors all --hot-only --format json

# Drive from a JSON config (CLI flags override):
python alloc_audit.py --config audit.config.json
```

### Detectors

| name          | what it flags |
|---------------|---------------|
| `delegate`    | `newobj` of a delegate (`.ctor(object, native int)`), classified **cached** (compiler `<>9__` lambda/method-group cache) vs **uncached** |
| `box`         | `box` opcode (value type boxed to `object`) |
| `newarr`      | array allocation |
| `collection`  | `newobj` of a generic collection (`List`/`Dictionary`/`HashSet`/`Queue`/`Stack`/…) |
| `linq`        | calls into `System.Linq.Enumerable` |
| `stringalloc` | `String::Concat`/`Format`/`Join` and `StringBuilder::.ctor` |

`--detectors all` enables every detector. Default is `delegate`.

### Config file

```json
{
  "assemblies": ["path/to/Assembly-CSharp.dll"],
  "detectors": ["delegate", "box", "stringalloc"],
  "hot_path": ["Update", "LateUpdate", "RecordRenderGraph"]
}
```

## Notes

- The `delegate` "cached" heuristic keys on the compiler's `<>9__` cache field. One-time
  allocations stored to a *named* field (e.g. a `static readonly` initialiser in `.cctor`)
  are reported as uncached but, being one-time, are filtered out by `--hot-path`.
- Method attribution uses ILSpy's `} // end of method <Name>` markers, so lambdas/iterators
  are attributed to their compiler-generated method (e.g. `'<>c'::'<Foo>b__1_0'`).
