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
  in parentheses or trailing, wherever the call is written. A call's value,
  and a declaration's, assignment's or return's, reuses the values its
  argument and receiver calls were visited with instead of evaluating them a
  second time. When the callback writes the assigned name itself
  (`u = wrap(u) { u = ... }`), the assigned value keeps what it wrote there,
  since the callback may run later; the closure of a standard function that
  runs it before returning (`also`, `let`, `map`, `withContext`, ...) and a
  lambda invoked where it is written (`{ .. }()`) write before the assignment
  stores.
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
  `when (val u = ...)` subject and Swift case patterns bind their names to
  the value they match, for their entries only (shadowing an outer name),
  also where the `when` or `switch` is a value outside closures (whose value
  is its entries', not the subject's): `case let x`, `case let x?` and
  `case .some(let x)` bind the subject itself, as `if let` does; a tuple
  pattern binds an element of a tuple literal subject (`switch (safe, link)`,
  `case (let a, _)`, also labeled or nested, and an enum payload inside an
  element); an enum case's associated value (`case .open(let url)`)
  carries the subject's sources and category and what is stored in its
  payload, without the enum's type or object identity. A label (`url:` in
  `case let .open(url: dest)`) binds nothing.
- A closure's value is its result: the last expression (Kotlin, Java expression
  bodies, single-expression Swift closures) and returns that leave the closure
  (`return@label`, Swift and Java `return`). An `if` without `else`, a
  statement and a body that always exits leave no last value; an
  `if`/`when`/`switch`/`try` leaves its branches' values, not its condition.
  Each branch value is read where the branch ends, so names the branch
  declares or binds (`{ val t = ...; t }`, Swift `if let`) keep their values,
  also in an unbraced inner `if`/`when`; comments between `when` entries and
  Swift's `try` operator do not hide it.
  The calls of the last expression are evaluated once, where the closure is
  followed, so an unresolved call's effects are not applied twice. When an
  unresolved call's value includes a closure's result, a trace-budget cut in
  that result, also one the closure only passes on, is recorded as a
  precision limit there (`source trace abstention`, `limited`): the callee
  may never return it. This also holds for a `let`, `run`, `with` or `use`
  block's result, which is its call's result: an own call in it
  (`x?.let { own(it) }` in an Activity) carries the field-round
  re-origination cut of unresolved own calls, and stays `limited` as in
  1.7.0; a block whose own result overflows the trace cap is `limited` too.
  `withContext { }`, `runCatching { }` and other results now carry their
  provenance. A predicate, comparator or per-element action (`filter`,
  `first`, `find`, `count`, `any`, `sortedBy`, `takeIf`, `forEach`, and the
  comparator builders `compareBy`, `thenBy`, `Comparator { }`, ...) decides
  what its call returns and is not part of the value, so an element of an
  app-owned allowlist picked with untrusted input is not reported.
  Lambda bodies are no longer re-evaluated by every enclosing call, so nested
  closures cost one evaluation per call instead of growing with the nesting
  depth, and a long `if`/`else if` or `when` chain in a closure is decided in
  linear time.
- When a call's value is used, what its closure writes into the objects the
  callee supplies is part of that value: the closure's parameters
  (`Html.build { b -> b.append(q) }`, Java `render(m -> { m.put("q", q); })`,
  Swift `render({ b in b.add(q) })`) and, for a Kotlin lambda without
  parameters, what it writes into a possible implicit receiver. Such a write
  is a statement (not a condition, an argument, an initializer or a thrown
  value): a receiverless call that is no constructor (`File(q)`,
  `IllegalStateException(q)`), no standard top-level function (`println`,
  `require`, `listOf`, ...) and no project function of a class, companion
  object or object around it, of a class it extends (also an extension of
  that class), or of the top level
  that this file can name, also through an import alias
  (`buildString { append(q) }`, `div { text(q) }`, `div { +q }`,
  `div { +format(q) }`, `request { parameter("q", q) }`; also in an unbraced
  `if`/`when`/`for`/`while` body), a chain it starts or a
  `this.` call (`append("<p>").append(q)`, `this.append(q)`; not a `this` an
  `apply`/`run`/`with` block rebound), a helper handed `this`
  (`appendFilter(this, q)`), a nested DSL
  call (`p { +q }`), and an assignment to a name that is no local or field
  (`request { url = q }`). A known builder's writing members (`append` in
  `buildString`, `add` in `buildList`, `put` in `buildMap`, `yield` in
  `sequence`, `emit` in `flow`, `send` in `channelFlow`, ...; for another
  `build…` callee, any of these names) are its receiver's even where a
  project function has that name; any other receiverless call in one of these
  builders is no member of its receiver, unless a project extension of the
  receiver type (`fun StringBuilder.appendSql(..)`). The lambdas of
  `withContext`,
  `runCatching`, `lazy`, `launch`, `async`, `synchronized`, `repeat`,
  `thread`, `remember`, ..., of SAM constructors and of composables
  (`Runnable { }`, `Column { }`) and of event-handler registrations
  (`b.onClick { }`, `setOnClickListener { }`, `doOnTextChanged { }`) have no
  such receiver; on a project or library object (`Sql.execute { }`,
  `Sql.Query { }`) such a name is that object's DSL. What a call writes is
  its data, whichever callee runs, and the result of a closure the receiver
  stores or takes as content (`m.getOrPut(k) { q }`, `b.section { q }`,
  `b.title { q.uppercase() }`, a DSL's `title { q }`; not a callback whose
  result is a side-effect call, `b.onClick { log(q) }`, Swift
  `b.onTap { [weak self] in self?.log(q) }`, nor the lazy message of an
  imported logger, `logcat { "msg $q" }`).
  Writes through a local alias (`val c = b`), a force-unwrap (`b!!`, Swift
  `b!`), a `let`/`also`/`use` block on it (`b.let { it.append(q) }`), a
  helper call written as a statement (also under Swift `try`, `await` or
  `_ =`) that is handed the object or a part of
  it (`fill(b, q)`, `Fill.paragraph(b.body, q)`, Java
  `Fill.into(m.getBody(), q)`, `m.getChild("body")`, either branch of a
  conditional, `parts.joinTo(b)`, `parts.joinTo(this)`; assumed
  to write its other arguments and its receiver into it; a value read from
  it, `b.length`, `b.id`, `m.getName()`, a reading member such as `b.contains(q)` or
  `b.contentEquals(q)`, and a helper in a condition write nothing), an index
  (`b.items[0].text = q`, Swift `m["q"] = q`) or a nested builder on it
  (`b.group { g -> g.append(q) }`) count too, and so does the builder call
  that is the single expression of a Swift function or getter. This restores
  1.7.0 findings for builder lambdas in parentheses and adds them for
  trailing ones.
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
as filled. A closure result over the trace cap that a call's value includes
(`Ext.io({ big })` with more than eight sources, or a `run { }` block's) is
`limited` (`source trace abstention`), where 1.7.0 reported the parenthesized
form `partial`. Kotlin `x!!` is the value of `x` for literal key and IV
tracking, filled buffers and intent-target checks:
`SecretKeySpec(key!!.toByteArray(), ..)` with a literal key is reported,
`nextBytes(raw!!)` fills `raw`, and a component check on `nested!!` is
credited. With `--strict-coverage`, `limited` exits 3 (a `--fail-on`
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
direct code. A helper handed a supplied object or a part of it in a
statement is assumed to write its other arguments into it (`put(b, q)` that
only prints `q` still counts), and a receiverless call in the lambda of an
unknown callee that names an inherited framework member
(`Ext.page { setTitle(q) }`) is taken as a write into its possible receiver.
What a helper writes from elsewhere (`fill(b)` reading its own input) and an
`apply`/`run`/`with` block on a declared supplied parameter are not tracked
(the latter is `limited`); `groupBy` keys taint the grouped elements. A project
function named like a DSL member (an own or top-level `text(s)`) hides that
DSL's `text(q)`, although Kotlin finds the lambda's receiver member first;
`+greet(q)` writes `q` even where `greet` returns a constant; a library
extension of a known builder's receiver (`buildString { appendXyz(q) }`) is
no write unless it is the lambda's last expression; a Swift tuple held in a
variable (`let pair = (safe, link); switch pair`) binds each element to the
whole tuple. An
exit inside a scope block (`run { return@outer }`) does not end the enclosing
statement list, so dead statements after it are still visited. Closures in
Kotlin class property initializers (`val listener = View.OnClickListener { }`,
`by lazy { }`) are not analyzed, as in 1.7.0. A value derived from a
collection element (a `forEach` parameter, `first()`, `[0]`) does not keep the
URL category, so a scheme/host check on it is not credited; `filter`
predicates and `when` conditions are not guards. Such an element has no type
either: in a class with supertypes, an own method it is passed to
(`marks.firstOrNull { trusted(it) }`) has no summary, and that unresolved call
weak-writes the class's fields, as `trusted(marks.first())` does in 1.7.0, so
a field read later can carry what another method stored (`partial`).
`registerForActivityResult`
results are not sources, and `require`/`check`/`takeIf` predicates are not
guards. Kotlin `suspend { }` lambdas still make tree-sitter-kotlin reject the
enclosing class. The evaluation budget is shared across the analysis: projects
with many followed calls can reach `recursion or call evaluation budget`
(`partial`) sooner, at the same cost per followed call as direct calls. Deeply
nested Swift closures (dozens of levels) cost superlinear time in type
lookups.
