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
- Every closure in an analyzed function body that is not a scope-function
  block (`let`, `also`, `use`, `apply`, `run`, `with`) is now followed once
  where it is written, in parentheses or trailing: click listeners,
  `runOnUiThread`, `post`, coroutine builders, `withContext`, `synchronized`,
  `repeat`, collection functions, Swift `DispatchQueue.async`, `URLSession`
  completion handlers and `UIView.animate`. Earlier releases inspected
  closures in parentheses without their guards and did not analyze trailing
  lambdas unless they contained a non-local `return`. A closure is a block
  that may not run: guards that hold where it is written apply inside it,
  guards it establishes never apply after it, its writes are merged as
  possible, and it reads captured locals as they are where it is written. A
  Kotlin lambda body is a statement list, so `if (...) { } else { return@label }`
  guards the statements after it and code after an unconditional
  `return@label` or `throw` is not visited. A closure marker no longer makes
  the whole closure body a condition of `AST-WEBVIEW-HOST-ALLOWLIST`.
- A call's receiver and data arguments are bound before its closures run: a
  callback that assigns an argument variable (`evaluateJavascript(js) { js = ... }`,
  `val r = attach(name) { name = ... }`) does not change that call's argument,
  in parentheses or trailing, as a statement or in a declaration, assignment or
  return. Those right-hand sides now reuse the values their visit computed
  instead of evaluating their calls a second time.
- Declared closure parameters are locals that shadow outer names; they carry no
  value. This removes false findings where a parameter had the name of a
  tainted local or of `intent`, also for closures in parentheses. A lambda that
  declares only `_` has no implicit `it`. The element parameter (or `it`, or
  Swift `$0`) of a known collection function (`forEach`, `map`, `filter`,
  `first`, `takeIf`, ...) keeps the receiver's provenance, as `first()` already
  did, and so do both parameters of `Map.forEach { key, value -> }` (also with
  `_`), Swift dictionary closures (`{ key, value in }`, `$1`) and a `reduce`
  accumulator; a `fold` accumulator carries the initial value and the
  elements. For other callees an implicit `it` still refers to an enclosing
  `it`. Declared parameter types are recorded (`entry: ZipEntry`). A Kotlin
  `when (val u = ...)` subject and Swift `case let` / `case .some(let u)`
  patterns bind their names to the value they match, also outside closures.
- A closure's value is its result: the last expression (Kotlin, Java expression
  bodies, single-expression Swift closures) and returns that leave the closure
  (`return@label`, Swift and Java `return`). An `if` without `else`, a
  statement and a body that always exits leave no last value; an
  `if`/`when`/`switch`/`try` leaves its branches' values, not its condition.
  Each branch value is read where the branch ends, so names the branch
  declares or binds (`{ val t = ...; t }`, Swift `if let`) keep their values;
  comments between `when` entries and Swift's `try` operator do not hide it.
  The calls of the last expression are evaluated once, where the closure is
  followed, so an unresolved call's effects are not applied twice. When an
  unresolved call's value includes a closure's result, a trace-budget cut in
  that result is recorded as a precision limit there (`source trace
  abstention`, `limited`): the callee may never return it.
  `withContext { }`, `runCatching { }` and other results now carry their
  provenance. A predicate, comparator or per-element action (`filter`,
  `first`, `find`, `count`, `any`, `sortedBy`, `takeIf`, `forEach`, and the
  comparator builders `compareBy`, `thenBy`, `Comparator { }`, ...) decides
  what its call returns and is not part of the value, so an element of an
  app-owned allowlist picked with untrusted input is not reported.
  Lambda bodies are no longer re-evaluated by every enclosing call, so nested
  closures cost one evaluation per call instead of growing with the nesting
  depth.
- When a call's value is used, what its closure writes into the objects the
  callee supplies is part of that value: the closure's parameters
  (`Html.build { b -> b.append(q) }`, Java `render(m -> { m.put("q", q); })`,
  Swift `render({ b in b.add(q) })`) and, for a Kotlin lambda without
  parameters, what it writes into a possible implicit receiver: receiverless
  builder writes (`append`, `add`, `put`, `set`, `emit`, `send`, ...) that name
  no project function, and assignments to names that are no local or field
  (`buildString { append(q) }`, `request { url = q }`). Another receiverless
  call (`println(q)`, `require(...)`) is no write. Writes through a local
  alias (`val c = b`), a scope block (`b.let { it.append(q) }`), a helper
  handed the object (`fill(b, q)`), an index (`b.items[0].text = q`) or a
  nested builder on it (`b.group { g -> g.append(q) }`) count too, and so does
  the builder call that is the single expression of a Swift function or
  getter. This restores 1.7.0 findings for builder lambdas in parentheses and
  adds them for trailing ones.
- A lambda passed to a project callee binds its function-typed parameter. In a
  class with supertypes, a closure literal whose arity matches the declared
  function type no longer blocks the callee summary. A callee that calls its
  lambda parameter (`done()`, `done.invoke(x)`) is `limited`
  (`callable value binding unresolved`): the lambda body is not re-run with
  the callee's arguments.
- An unresolved call is not assumed to store a closure's result into the
  objects it can reach, except the standard APIs that store it into their
  receiver (`compute`, `computeIfAbsent`, `computeIfPresent`, `merge`,
  `replaceAll`, `updateAndGet`, `getAndUpdate`, `accumulateAndGet`,
  `getAndAccumulate`, `getOrPut`, `update`). A 1.7.0 finding that came from
  another unresolved callee storing a closure's result (`h.provide({ src })`
  read back from `h`) is no longer reported; coverage stays `limited`. A
  closure's result is no object the callee can reach, so an object a closure
  creates (`synchronized(lock) { Cache() }`, `runCatching { Parser() }`) adds
  no reference-effect reason, and a closure argument alone no longer records
  `unresolved callable identity`.
- Unshadowed standard scope functions with a lambda block are modelled by the
  analyzer itself and add no unresolved-callable reason. `use` still takes the
  unresolved-call path, which covers its `close()`, and a function reference
  block (`also(::fill)`, `let(this::f)`) is an unresolved call (`limited`).
- A Kotlin default value is no longer read as an extra parameter, and a
  Swift/Kotlin result type is read from the declaration, so a `() -> Void` or
  explicit `: Unit` no longer records `return flow unavailable`.

## Coverage changes

Code that was silently skipped is now examined, so some reports change state:
findings appear where sinks sit in closures, and precision reasons that were
hidden become visible. Typical SwiftUI apps report `limited`: memberwise
initializers of the app's own views (`constructor field mapping unavailable`),
environment actions such as `dismiss()`, computed-property reads, `@State`
writes and model calls in view-builder and button closures are precision
limits; SwiftUI's own views (`VStack`, `List`, `ForEach`, `.sheet`) remain
credited. In Jetpack Compose code, a call to the app's own composable that
leaves a defaulted parameter (`modifier: Modifier = Modifier`) before its
trailing `content` lambda is now read as that call and is not followed
(`limited`, `unresolved callable identity or argument signature`). Kotlin
`requireNotNull(x) { }`, `require`, `check` and `repeat(n) { }` report
`limited` when their data argument carries input, and `synchronized(this) { }`
passes `this` to an unresolved call, as their parenthesized forms did in
1.7.0; with a wildcard import, `with` is not provably the standard function. A
literal key or IV that is only named inside a closure is now reported; one a
closure may fill (passed to a call or written element by element) is treated
as filled. With `--strict-coverage`, `limited` exits 3 (a `--fail-on`
threshold exits 4).

## Remaining limits

A callee does not bind a lambda's parameters when it calls the lambda, and a
trailing lambda is not bound past a defaulted parameter (`limited`). Receiver
lambdas of unknown calls (`db.transaction { execSQL(...) }`) do not bind
`this`, and a write into a scope function's receiver object without identity
(`StringBuilder().apply { append(q) }`) is not tracked. Deferred callbacks are
merged as if they could run before the following statements, and they read
captured locals as they are where they are written. A loop variable inside a
builder closure (`for (p in parts) b.append(p)`) carries no value, as in
direct code, a project helper that writes into a supplied object (`put(b, q)`)
is not tracked, and `groupBy` keys taint the grouped elements. An exit inside
a scope block (`run { return@outer }`) does not end the enclosing statement
list, so dead statements after it are still visited. Closures in Kotlin class
property initializers (`val listener = View.OnClickListener { }`,
`by lazy { }`) are not analyzed, as in 1.7.0. A value derived from a
collection element (a `forEach` parameter, `first()`, `[0]`) does not keep the
URL category, so a scheme/host check on it is not credited; `filter`
predicates and `when` conditions are not guards. `registerForActivityResult`
results are not sources, and `require`/`check`/`takeIf` predicates are not
guards. Kotlin `suspend { }` lambdas still make tree-sitter-kotlin reject the
enclosing class. The evaluation budget is shared across the analysis: projects
with many followed calls can reach `recursion or call evaluation budget`
(`partial`) sooner, at the same cost per followed call as direct calls.
