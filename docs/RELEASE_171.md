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
  (`u = wrap(u) { u = ... }`), the assigned value keeps what its assignments
  stored there (also an alias of the value from before, `u = requested`, but
  not that value where a branch does not assign), since the callback may run
  later, unless a local of that name declared before it in the callback (also
  in a nested block or lambda, a destructuring declaration, a Swift
  `guard var` binding, or an `if var` binding in its then-block) is what it
  assigns; the closure of a standard
  function that runs it before returning (`also`, `let`, `map`, `withContext`,
  ...) and a lambda invoked where it is written (`{ .. }()`) write before the
  assignment stores.
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
  is its entries', not the subject's; a braced entry's value is its last
  statement, read with the entry's own locals, `else -> { val v = u.trim(); v }`):
  `case let x`, `case let x?` and
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
  depth, and a long `if`/`else if` or `when` chain or a long flat builder body
  in a closure is decided in a linear number of steps (tree-sitter's parent
  walk still costs more on deep nesting: about n^1.6 in wall time for a long
  value `else if` chain in a closure).
- When a call's value is used, what its closure writes into the objects the
  callee supplies is part of that value: the closure's parameters
  (`Html.build { b -> b.append(q) }`, Java `render(m -> { m.put("q", q); })`,
  Swift `render({ b in b.add(q) })`) and, for a Kotlin lambda without
  parameters, what it writes into a possible implicit receiver. Such a write
  is a statement (not a condition, an argument, an initializer or a thrown
  value; an `if`/`when` branch, the last statement of a `let`/`run`/`with`
  block, an elvis fallback, a scope block before `?:`
  (`x?.let { text(it) } ?: footer()`) and a labeled or parenthesized expression
  are statements only where the `if`, `when`, block or expression itself is
  one, so `val ok = if (c) allowed(q) else true` writes nothing; the result of
  a mapping lambda (`map`, `associateBy`, `groupBy`, `fold`, `sumOf`,
  `maxOfOrNull`, `joinToString`, ...) is a statement where the call is, of a
  `*To` function (`mapTo`, `associateByTo`, `groupByTo`, `mapKeysTo`, ...)
  never, as its destination stores it, and of a `runCatching` block where its
  Result chain of `also`, `map`, `fold`, `onSuccess`, `onFailure`,
  `getOrNull`, ... ends
  (`runCatching { text(q) }.onFailure { .. }` writes,
  `val r = runCatching { parse(q) }.getOrNull()` does not); an elvis chain's scope blocks
  (`a?.let { .. } ?: b?.let { .. } ?: c`) run where the chain is, but a plain
  fallback an outer elvis tests is a value (`cached ?: load(q) ?: return`, also
  parenthesized, `(cached ?: load(q)) ?: return`); a loop
  without a body, `while (advance(q));`, has none; a predicate's result,
  `filter { }`, `filterTo { }` or `takeIf { }`, is none; a known builder's writing member
  writes wherever it stands, `val added = add(q)`): a receiverless call that
  is no constructor (`File(q)`,
  `IllegalStateException(q)`), no standard top-level function (`println`,
  `require`, `listOf`, ...) and no project function of a class, companion
  object or object around it, of a class it extends (also an extension of
  that class), or of the top level
  that this file can name, also through an import alias
  (`buildString { append(q) }`, `div { text(q) }`, `div { +q }`,
  `div { +format(q) }`, `request { parameter("q", q) }`; also in an unbraced
  `if`/`else`/`when`/`for`/`while`/`do`-`while` or labeled body and as an
  elvis fallback, `n ?: append(q)`), a chain it starts or a
  `this.` call (`append("<p>").append(q)`, `this.append(q)`; not a `this` an
  `apply`/`run`/`with` block inside the lambda rebound), a helper handed `this`
  (`appendFilter(this, q)`), a nested DSL
  call (`p { +q }`), and an assignment to a name that is no local or field
  (`request { url = q }`), also `this += q` and `this["k"] = q`. A known
  builder's writing members (`append`, `appendln`, `insert`, `setCharAt` in
  `buildString`; `add`, `set`, `fill`, `replaceAll` in `buildList`; `put`,
  `merge`, `compute`, `computeIfAbsent`, `replace` in `buildMap`; `insert`,
  `appendLine` and the span helpers in `buildSpannedString`; the annotation
  members of `buildAnnotatedString`; `yield` in `sequence`; `emit` in `flow` and
  in the Flow operators `onStart`, `onEmpty`, `onCompletion` and
  `onSubscription`; `send` and `channel.send` in `channelFlow`, ...; for another
  `build…` callee, any of these names) are its receiver's even where a
  project function has that name; any other receiverless call in one of these
  builders is no member of its receiver, unless a project extension of the
  receiver type or a writable supertype (`fun StringBuilder.appendSql(..)`,
  `fun Appendable.appendQuoted(..)`, `fun MutableCollection<String>.addTagged(..)`, also
  through a type parameter's bound or a project typealias). Such a lambda
  returns `Unit`: the builder's value is what it writes and its final
  statement (each branch of a final `if`/`when`) unless that is a call on an
  object, a constructor's chain or property (`File(dir, q).delete()`,
  `Pair(q, 1).first`) or a non-writing function (a final
  receiverless call chain may be a library extension of its receiver,
  `buildString { appendHTML().html { } }`);
  `buildString { ..; Log.d(t, q) }` and `.. else Log.d(t, q)` add nothing. Only
  another `build…` callee takes these member names; `repo.flow { append(q) }`
  is another object's DSL, where a project `append` binds. The lambdas of `withContext`,
  `runCatching`, `lazy`, `launch`, `async`, `launchWhenStarted`,
  `repeatOnLifecycle`, `synchronized`, `repeat`,
  `thread`, `remember`, ..., of SAM constructors and of composables
  (`Runnable { }`, `Column { }`) and of event-handler registrations
  (`b.onClick { }`, `setOnClickListener { }`, `doOnTextChanged { }`,
  `doAfterTextChanged { }`) have no such receiver; on a project or library
  object (`Sql.execute { }`, `dsl.remember { }` for the standard top-level
  runners; not a constructor or factory call such as `Handler(..).post { }`)
  such a runner name is that object's DSL; coroutine builders have a scope
  receiver on any object. The standard builders take their member table
  only without a receiver, through their package (`kotlinx.coroutines.flow.flow { }`)
  or (`produce`) on a scope; `repo.flow { }`, `repo.store.flow { }` and an app
  package's `com.myapp.db.flow { }` are other DSLs. What a call writes is
  its data, whichever callee runs, and the result of a closure the receiver
  stores or takes as content (`m.getOrPut(k) { q }`, `b.section { q }`,
  `b.section { return@section q }`, `b.title { q.uppercase() }`, a DSL's
  `title { q }`, also one this file imports, a Java supplier
  `m.section(() -> q)`: a value, or a call whose call chain starts at data: a
  literal, a value class such as `String`, a local the closure (or the braced
  branch it ends in, whose own locals hide the closure's of that name)
  declares from data or from an expression that would be content as the closure's
  result and carries input, also by assigning it later (`{ val t = q.trim(); t.uppercase() }`,
  `{ val t = repo.lookup(q).trim(); t }`, Java
  `{ String u = TPL.concat(q); return u; }`, `String label; .. label = q.trim();`,
  `var c: String? = null; if (..) c = "n = '$q'"; c`). All of a local's
  values are classified until references to later locals and self updates stabilize;
  nested blocks use their own locals, and assignments in inline scope lambdas
  also count (`q.let { c = "n = '$it'" }`), except to a shadowing local or parameter;
  a local can hold a computed call-result expression (`val r = repo.find(q);
  val t = r + "x"; t`),
  a value factory, a source call itself, or an own function this file
  declares to return a String, also a Swift `throws` or `async` one and a
  Kotlin expression body that is a String initializer or a String property
  (`fun profileUrl() = ".." + handle`), also called on `this` or `self`, the
  enclosing class's own function of that name deciding (`listOf(title, q)`,
  `StringBuilder(q)`, `getIntent()`, `displayName()`,
  `this.displayName().escapeSql()`; another call's result is data only through a String
  transform, below, and an object built from input is none, also from a
  closure's own local, `Uploader(q).start()`, `File(dir, t).delete()`), a
  computed expression over data, or over a closure's call result joined with
  input from outside it or closure data, also among the other arguments of a
  call over that result (`(col + " = '" + q + "'").escapeSql()`,
  `(Ext.quote(col, q) + " ASC")`, `(Ext.wrap(t) + col)`; not
  `(Ext.wrap(col) + "x")`), a local or
  parameter holding input (`q.substring(0, q.length - 1)`), or a field or other reference holding an
  input value (`field = q`, `this.field`, never a local of the member's name,
  `intent` in `intent.getStringExtra("q")`, a String property, primary-
  constructor property (also `String?`) or Java String field holding a value
  derived from input, `query = q.trim()`, also through its class or object
  from another file, `Session.query`, `com.example.Session.query`), also a
  qualified value class
  (`java.net.URLEncoder.encode(q, ..)`, `Optional.ofNullable(q)`), or a String
  that the String transforms starting the chain fill with input, held in a
  name declared as a String or initialized from a string literal (also `+`
  with one, a raw string's `trimIndent()`, `getString(..)`), a property, a
  companion, object or top-level constant (the enclosing class's own property
  of that name decides, not a same-named String elsewhere in the file;
  without one, a bare name or `this.`, `self.` or `super.` reads a String of
  that name in the file or one a source supertype declares, also in another
  file for Kotlin and Java (Swift source supertypes are read within the same
  file), Java `class Page implements Urls` reading `SEARCH`), also qualified,
  also by its package (`com.example.Sql.BY_NAME`), and from another file, a
  Java interface's constants included, filled through its new text (by its
  name in `replace(newValue = q, oldValue = "{q}")`)
  (`template.format(q)`, `prefix.plus(q)`, Java `TPL.formatted(q)`,
  `this.template.replace("{q}", q)`, `Sql.BY_NAME.format(q)`,
  `q.let { tpl.format(it) }`, `tpl.replace(Regex("x")) { q }`; not
  `template.replace(q, "x")`); a String
  transform of a call's result over input, also through a closure local
  (Kotlin, Java or Swift, also a Swift `guard let`, typed or shorthand) and
  its `run`/`with`
  blocks, `ifBlank { }`, `also { }` or `takeIf { }` (`repo.lookup(q).trim()`,
  `{ val t = repo.lookup(q); t.trim() }`, `t.run { trim() }`,
  `with(t) { uppercase() }`, but not `t.track("open")`; a nested `with`/`run`
  rebinds `this`, so `with(repo.find(id)) { with(fmt) { format(d) } }` is no
  content); a value class or standard collection built in the
  closure (`String(format: "%@", q)`, `URL(string: q)`, `listOf(title, q)`,
  `Pair(title, q)`, `requireNotNull(q)`); a `let`/`run`/`with` block's result,
  also a receiverless `run { }`'s (`q.let { it.trim() }`,
  `title?.let { "$it: $q" }`, `q.run { trim().lowercase() }`,
  `q.run { split(",").first() }`, `with(q) { val t = trim(); t.uppercase() }`,
  `run { "$prefix/$q" }`); not a flag or a number (a comparison or logical
  operation, `q == "x"`, `q in xs`, a member such as `q.isNotEmpty()`,
  `q.length` or `template.contains(q)` (not `this.size` when the class's own
  `size` is a String), a call on a number class or type,
  `Integer.parseInt(q)`, `java.lang.Long.parseLong(q)`, `Math.max(1, n)`,
  Swift `Int(q)`, a closure's local or `let` parameter that holds one or is
  declared as one, `val n = q.length`, `val ok: Boolean = check(q)`,
  `q.length.let { n -> .. }`, arithmetic, operations (`n.plus(1)`,
  `n.coerceAtLeast(1)`, `n.coerceIn(1, 100)`), self updates (`n = n + 1`)
  and elvis fallbacks on them, `q.length + 1`,
  `q.toIntOrNull() ?: 0`, Swift `Int(q) ?? 0`, branches or a ternary of
  them (`if (c) 0 else q.length`), their text, `q.length.toString()`,
  `n.toString()`, `"" + q.length()`, Swift `n.description` or `String(n)`,
  Java `String.valueOf(n)`, or a string that only interpolates them or a
  template that only they fill, `"${q.length} results"`, `"$n results"`,
  `"LIMIT %d".format(q.length)`, `val n = q.length; template.format(n)`,
  Java `String.format("LIMIT %d", n)` and `"LIMIT %d".formatted(n)`, Swift
  `String(format: "%d", n)`, or a numeric branch with a constant-text fallback,
  `if (c) n.toString() else "0"`), `Unit` or `null`, nor a closure's local
  whose values are only other calls' results, objects or flags, as the value
  itself (`{ val row = repo.find(q); row }`). A fill that inserts input after
  number text is content (`n.toString().plus(q)`, Swift `String(n).appending(q)`);
  also for a helper handed the object,
  `Fill.into(b) { q }`; not a callback whose result is a side-effect call,
  `b.onClick { log(q) }`, `b.button { analytics.track(q) }` (also a tracker
  held in a local or parameter),
  `b.section { q.let { audit.log(it) } }`, `forEach`, Swift
  `b.onTap { [weak self] in self?.log(q) }`, nor the lazy message of a
  logging function imported by name or through a star import of a logging
  package, `logcat { "msg $q" }`).
  Writes through a local alias (`val c = b`), a force-unwrap (`b!!`, Swift
  `b!`), a `let`/`also`/`use` block on it (`b.let { it.append(q) }`), a
  helper call written as a statement (also under Swift `try`, `await`, `_ =`
  or `let _ =`) that is handed the object or a part of
  it (`fill(b, q)`, `Fill.paragraph(b.body, q)`, `b.title`, `b.text`, Java
  `Fill.into(m.getBody(), q)`, `m.getText()`, a getter with literal or
  constant keys, `m.getChild("body")`, `b.child(0)`, `b.child(MAIN)`, either
  branch of a conditional, also a Java `switch` expression, `parts.joinTo(b)`,
  `parts.joinTo(this)`, through a chain of up to 255 getters; assumed to write
  its other arguments and its receiver into it; a value read from it,
  `b.length`, `b.id`, `m.getName()`, a flag, `b.isReady`, `m.hasBody()`,
  `b.enabled`, a keyed scalar read, `b.getInt("rows")`, `m.optString("k")`,
  `doc.attr("id")`, a reading member such as `b.contains(q)` or
  `b.contentEquals(q)`, a helper in a condition, and a logging or analytics
  call (on a receiver named `log`, `timber`, `tracker`, `metrics`, `sentry`,
  ..., also after `m`, `m_`, `s_` or `_`, or `s` as a camel-case word
  (`mLog`, `_logger`, `m_logger`, `sLog`; not `slog`), a log named by an
  App, My, Debug, Base, Common, File, Remote, Crash or Error word (`debugLog`,
  `app_log`; not `eventLog`, `audit_log`), a logger or analytics name after
  snake-cased words
  (`app_logger`, `firebase_analytics`; not `change_log`, `call_log` or
  `app_metrics`), ending in `Logger`, `Analytics`, `Crashlytics` or
  `Telemetry` as a camel-case word (`appLogger`, `LOGGER`; not `blogger`), a
  tracker or tracking named by a camel-case or snake-cased word for
  analytics, events, screens, usage, users, the app, errors, crashes or an
  analytics vendor, with at most a view, event, action, click, activity,
  session or engagement word between (`screenViewTracker`,
  `userSessionTracker`, `userTracking`, `AppsFlyerTracker`,
  `screen_view_tracker`; not `selectionTracker`, `selection_tracker`,
  `appStateTracker` or `orderTracking`), a logging wrapper named `Log` +
  `Utils`, `Helper` or
  `Wrapper`, also after `m`, `s` or `_` or an `App`, `My`, `Debug`, `Base`,
  `Common`, `File`, `Remote`, `Crash` or `Error` word (`LogUtils`,
  `mLogHelper`, `AppLogHelper`, `appLogHelper`; not `CallLogHelper` or
  `ChangeLogUtils`), or
  `System.out`/`err`: `Log.d(TAG, b.body)`,
  `Timber.d("%s", this)`, `mFirebaseAnalytics.logEvent(..)`,
  `analyticsTracker.track(b.text, q)`), write nothing;
  `b.label`, `b.tag` and `b.code` may be parts), an index
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
form `partial`. A local initialized from a string literal is a String, so
`var s = ""; s += q` concatenates where 1.7.0 recorded `compound assignment
operator dispatch unavailable`. Kotlin `x!!` is the value of `x` for literal key and IV
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
no write unless a call chain it starts is the lambda's last expression, and a
member extension declared in a companion object is not found; a receiverless
`also { it.append(q) }` in a builder is not tracked; a chain of 256 or more
calls or getters is cut (`limited`); a content lambda whose result is a call on
an object that carries no input itself is a side effect
(`b.section { Json.encodeToString(q) }`); a branching content result
whose branches mix a value and a side-effect call or a call's result held in
a local writes every branch's value (`if (a) "x" else audit.record(q)`,
`if (a) { val t = repo.find(q); t } else "-"`); a `let` parameter over a
value that is neither data nor a call's result is read as another call's
result, so a String transform on it is content (`fmt.let { it.format(d) }`,
`limited`); a template a call returns is not filled
(`Store.base().concat(q)`), and a member of another object named like a
number (`filter.size`) is a number; a number held in a name declared
outside a content lambda is read like any value, as a direct sink reads it
(`val n = q.length` before `b.section { "$n results" }`), and an own
function declared in another file is not known to return a String; logging is recognized by the
receiver's name, so a writer held in a logger-like name
(`mLog.append(b.body, q)`, `metrics.fill(b.body, q)`) writes nothing and an
unlisted logging wrapper (`L.d(b.body, q)`) is a helper that writes; tree-sitter-kotlin 1.1.0 reads a
`where(..)` (also `by(..)`, `constructor(..)`) call on the line after another
statement, also a declaration or assignment, as an infix call of that name,
which in a followed lambda still writes, after the line before it declares or
assigns its name (`val c = "..$q"` then `where(c)`; glued onto the last
operand of an elvis, comparison or if/else value it reads that name unbound),
as does a call on the line before it, but elsewhere is not followed; a
member read through a labeled `this` (`this@Screen.field`) has no value of its
own; a capitalized DSL entry
point (`Sql.Query { }`) is taken as a SAM constructor, so its writes are not
followed; a Swift tuple held in a variable (`let pair = (safe, link); switch
pair`) binds each element to the whole tuple. An
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
