# APSA 1.7.1

Package version: `1.7.1` (pending). Rule version: pending.

This release follows the 1.7.0 limits. It was developed and checked against
source and fresh synthetic fixtures; no app code was executed and no device or
credential service was contacted.

## Trailing lambdas and closures

- A Kotlin call written with parentheses and a trailing lambda (`f(x) { }`,
  `o.f(x) l@{ }`, `f<T>(x) { }`) is the same call as `f(x, { })`. Earlier
  releases read it as a call named `f(x)` with no arguments, so its arguments
  were not checked, a sink such as `evaluateJavascript(js) { }` or a project
  specification sink was missed, and the call was not followed into the
  callee, while coverage stayed `checked`. Swift trailing closures, including
  the nested form in property initializers (`let task = f(x) { }`, also with
  `try`/`await`) and multiple trailing closures, are arguments the same way.
  A trailing closure matches a Swift parameter by position: the first one
  drops its label and each further one is checked against its label. A
  Kotlin named argument must name the parameter it binds; a reordered call is
  not followed (`limited`) instead of being bound by position.
- Every closure that is not a scope-function block (`let`, `also`, `use`,
  `apply`, `run`, `with`) is now followed once where it is written, in
  parentheses or trailing: click listeners, `runOnUiThread`, `post`,
  coroutine builders, `withContext`, `synchronized`, `repeat`, collection
  functions, Swift `DispatchQueue.async`, `URLSession` completion handlers and
  `UIView.animate`. Earlier releases did not analyze trailing lambdas unless
  they contained a non-local `return`. A closure is a block that may not run:
  guards that hold where it is written apply inside it, guards it establishes
  never apply after it, and its writes are merged as possible. A Kotlin lambda
  body is a statement list, so `if (...) { } else { return@label }` guards the
  statements after it and code after an unconditional `return@label` is not
  visited. A closure marker no longer makes the whole closure body a condition
  of `AST-WEBVIEW-HOST-ALLOWLIST`.
- Declared closure parameters are locals that shadow outer names; they carry no
  value. This removes false findings where a parameter had the name of a
  tainted local or of `intent`, also for closures in parentheses. The element
  parameter (or `it`, or Swift `$0`) of a known collection function
  (`forEach`, `map`, `filter`, `first`, `takeIf`, ...) keeps the receiver's
  provenance, as `first()` already did. For other callees an implicit `it`
  still refers to an enclosing `it`. Declared parameter types are recorded
  (`entry: ZipEntry`).
- A closure's value is its result: the last expression (Kotlin, Java expression
  bodies, single-expression Swift closures) and returns that leave the closure
  (`return@label`, Swift and Java `return`). `withContext { }`,
  `runCatching { }` and other results now carry their provenance. Lambda
  bodies are no longer re-evaluated by every enclosing call, so nested closures
  cost one evaluation per call instead of growing with the nesting depth.
- A lambda passed to a project callee binds its function-typed parameter. In a
  class with supertypes, a closure literal whose arity matches the declared
  function type no longer blocks the callee summary. A callee that calls its
  lambda parameter (`done()`, `done.invoke(x)`) is `limited`
  (`callable value binding unresolved`): the lambda body is not re-run with
  the callee's arguments. An unresolved call is not assumed to store a
  closure's result into the objects it can reach, and a closure argument alone
  no longer records `unresolved callable identity`. Unshadowed standard scope
  functions are modelled by the analyzer itself and add no unresolved-callable
  reason.
- A Kotlin default value is no longer read as an extra parameter, and a
  Swift/Kotlin result type is read from the declaration, so a `() -> Void` or
  explicit `: Unit` no longer records `return flow unavailable`.

## Coverage changes

Code that was silently skipped is now examined, so some reports change state:
findings appear where sinks sit in closures, and precision reasons that were
hidden become visible. Typical SwiftUI apps report `limited`: memberwise
initializers of the app's own views, environment actions such as `dismiss()`,
computed-property reads and `@State` writes in view-builder closures are
precision limits (SwiftUI's own views remain credited). With
`--strict-coverage`, `limited` exits 3 (a `--fail-on` threshold exits 4).

## Remaining limits

A callee does not bind a lambda's parameters when it calls the lambda, and a
trailing lambda is not bound past a defaulted parameter (`limited`). Receiver
lambdas of unknown calls (`db.transaction { execSQL(...) }`, `buildString`) do
not bind `this`. Deferred callbacks are merged as if they could run before
the following statements. `registerForActivityResult` results are not sources,
and `require`/`check`/`takeIf` predicates are not guards. Kotlin `suspend { }`
lambdas still make tree-sitter-kotlin reject the enclosing class. The
evaluation budget is shared across the analysis: projects with many followed
calls can reach `recursion or call evaluation budget` (`partial`) sooner.
