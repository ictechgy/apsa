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
- Receiverless String transforms in Kotlin `run`/`with`/`apply` scopes read the
  bound receiver after project-callee resolution, including ordinary sinks
  (`q.run { db.execSQL(trim()) }`). A nested `buildString` supplies the nearer
  receiver for applicable CharSequence operations and Regex replacements. String-only
  operations keep their outer String receiver; an intervening collection owns its
  applicable operations, while a nested scope can rebind the receiver again.
  Named Regex replacement arguments bind by label, and inferred local numeric
  and Regex kinds participate in these checks. A rebound String leaves the
  three-argument StringBuilder replacement to an applicable outer builder.
  Resolved project returns precede same-named Regex factory hints.
  Resolved project helpers keep their actual return provenance and declared return
  kind. Recognized numeric signatures check required arity, argument labels and
  compatible known kinds before taking precedence, including signed/unsigned
  operands, min/max bounds, adaptive integral literals and radix receivers.
  Identified String no-argument reads,
  `plus` and `format` precede outer class and top-level helpers, while lexical
  local functions retain their own dispatch. String signatures check argument
  labels, Locale and named-vararg array kinds before overriding project helpers.
  Visible project extensions on compatible receiver types prevent the standard
  extension shortcut; incomplete project extension receiver flow is `limited`.
  String members `plus` and `toString` still precede extensions. Retained local
  kinds follow the selected modeled result, and untyped callback parameters
  clear inherited kinds. Proven non-receiver scope functions preserve outer `this`.
  Inferred return queries isolate the declaring function from caller owner,
  parameter, field and retained-value state, restoring it after failure. Unknown
  inherited return identifiers remain visibly limited. Safe member results
  preserve Kotlin nullability, including an unnecessary safe call on a nonnull
  receiver; consuming safe entry and assertions retain their own policy.
  Retained text cannot erase nullable return identity, and indexed/fold callback
  hints keep original parameter positions across discarded `_` slots.
  Detached initializer hints abstain before function-bound or library-name
  inference and keep consumed uncertainty visible. Source/import receiver
  identities remain tied to declarations rather than same-named caller types.
  Receiver proofs only read retained values and do not execute unvisited calls.
  Represented module types avoid an unrelated identity reason while retaining
  any actual value-flow limit. Unlisted callback receiver types stay visibly
  conservative; general initializer flow remains separately scoped.
  Qualified generic roots, lexical class shadows and visible source typealiases
  are resolved in their declaring context with a bounded, cycle-safe lookup.
  Compatible String supertype extensions include `Comparable<String>`, star and
  contravariant projections, generic bounds and JVM `Serializable`; incompatible
  concrete type arguments retain standard dispatch. Their incomplete receiver
  flow is explicitly `limited`, only after a String subject is established.
  Applicable numeric members retain their result kind before outer helper returns.
  Reference-argument facts retain their declared nullability and binding origin
  across parameters, locals, fields and declared project returns. Constructor
  signatures see their class's member types. Nullable Array identities remain
  explicitly limited, including smart casts not represented by these hints.
  Kotlin floating literals retain Float/Double kinds. Nested numeric type hints
  reuse argument kinds, preserve the depth bound and never evaluate scalar
  provenance to establish a missing type. Unproven numeric signatures do not
  borrow a helper return kind. Opaque Comparable alias arguments conservatively
  retain the documented project-extension precision limit.
  Reference lookup includes lambda, loop, catch and when bindings; discarded
  lambda parameters do not introduce implicit it. Plain constructor parameters
  keep their initialization-only scope. Qualified field facts retain the owning
  declaration's type context. String/numeric receiver hints share bounded,
  frame-local query facts, and numeric classification abstains on an unknown
  operand kind without recursive scalar-provenance evaluation. Unproven
  numeric/String alternatives in an implicit receiver tower remain explicitly
  limited, including shared operation names on directly evaluated calls. Other
  incompatible or unknown receiver kinds are not a complete tower model.
  Loop and when bindings exclude their own initialization expressions;
  destructuring names block enclosing type facts. Element callback reference
  facts retain simple declared standard-container element types. Static or
  package-qualified class selection cannot borrow an instance field's type.
  Branch reference results preserve nominal facts; unproven result expressions
  abstain with a precision reason. Reference queries share facts within their
  sixteen-level bound, and receiver queries share successful facts and depth-aware
  unknowns within one frame. Ordinary unused type-hint cutoffs do not add a
  precision reason. A content classification that lacks a scalar operand's kind
  may retain a conservative helper finding with a visible precision limit,
  including compound operand expressions. A represented numeric receiver with
  an unproven kind also records that limit when consumed.
  Empty-body for loops exclude the iterable from binder visibility. Callback
  nominal facts distinguish elements, accumulators and indices; component and
  explicit-generic patterns abstain without independent facts. Reference cast
  queries retain target spelling and safe-cast nullability. Standard class heads
  do not override represented implicit-receiver values or inherited fields.
  Escaped function names share normalized lookup keys. Required parameters still
  constrain vararg candidates, and literal String arguments exclude proven
  incompatible primitive parameters. Compatible visible extension heads on
  represented implicit receivers prevent false constructor facts. Qualified
  retained hints check their complete spelling and value namespace roots.
  Optional numeric identity queries retain real execution budgets without
  reporting unconsumed identity uncertainty. Conservative constructor identity
  checks also apply outside library arguments and can leave fixed source members
  visibly limited under an unavailable external receiver.
  Positional literal checks stop at varargs instead of binding their later
  elements to defaulted parameters. Qualified allocations also exclude visible
  module-value roots. Import aliases compete only with the actual imported
  callable identity, preserving genuine constructor aliases and extension aliases.
  Primitive-looking generic parameters and aliases require declaration-origin
  proof before literal arguments can exclude their callables. Rejected generic
  extension candidates do not emit unused identity diagnostics. CharSequence
  no longer assumes Comparable or Serializable supertypes; broader numeric
  generic compatibility and project-instance receiver flow remain bounded.
  Same-file imported value aliases now block false package allocations. Parameter
  applicability probes include modeled names in their optional context, resolve
  renamed primitive aliases, and check vararg elements. Generic head competition
  follows alias and parameter bounds with a bounded, conservative query.
  Qualified constructor competition reads shallow, origin-sensitive argument facts
  after proving a relevant primitive parameter. It retains nullable String nominal
  identity and established ordinary-local facts without starting fresh recursive
  inference. Unknown applicability preserves possible source construction with an
  affected precision reason. Proven value-only Kotlin imports do not hide package
  qualifiers in TYPE positions. Java uppercase method names do not create
  allocations; explicit new expressions retain their constructor behavior.
  Represented builder extensions respect declaration visibility and distinguish
  unrelated source StringBuilder classes from the standard receiver. General
  overload ranking, Java vararg dispatch and inferred library returns remain
  bounded limitations.
  Active scopes on unshadowed supplied objects keep their public builder member
  extensions; unrelated, locally shadowed and private-owner controls stay excluded.
- Swift guard bindings become visible to subsequent clauses after their own
  initializers, remain available after success, and stay outside the else body.
  Format calls retain their visited fills, including Swift closure locals and
  Kotlin receiverless `run`/`with` templates. Input-free and numeric-only fills
  contribute no input text. Writes into supplied objects are classified at their
  written expressions: an earlier call's result alone remains a call result;
  its recognized String transform and an input-bearing qualified field are
  content. A known StringBuilder's final library-call contribution is preserved
  separately from writing members' return receivers. Stringifying a protocol
  receiver such as FlowCollector does not read its emitted payloads.
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
  elements. Unshadowed top-level repeat supplies an Int index. Established
  parameterless/receiver callbacks keep an enclosing it; unknown call-argument
  callback parameter identities abstain with a precision reason rather than
  proving the enclosing binding's type. Their conservative provenance can still
  retain an enclosing source. Declared parameter types are recorded (`entry: ZipEntry`). A Kotlin
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
  unresolved call's value includes a closure's result, a duplicate-route-only
  trace cut can be a precision limit there (`source trace abstention`,
  `limited`): the callee may never return it. Actual loss of more than eight
  distinct input locations remains `partial / source trace budget`, including
  when the closure only passes it on. The duplicate-route exception also holds
  for a `let`, `run`, `with` or `use` block's result: an own call in it
  (`x?.let { own(it) }` in an Activity) carries the field-round
  re-origination cut of unresolved own calls, and stays `limited` as in
  1.7.0. A block whose result exceeds the distinct-source cap stays `partial`.
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
  `div { +format(q) }`, `div { +_format(q) }`, `request { parameter("q", q) }`; also in an unbraced
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
  values are classified by lexical binding and source position with a dependency
  worklist; kinds accumulate until aliases and self updates stabilize. A bounded
  classification-work cut records `partial` (`closure value classification budget`);
  nested blocks use their own locals, and assignments in inline scope lambdas
  also count (`q.let { c = "n = '$it'" }`), except to a shadowing local or parameter;
  supplier branches contribute their returned values, including Java switch
  arms and yields and Kotlin `when (val x = ..)` subject bindings, not their
  selectors, predicates or logging statements; explicit writes into a supplier's
  provided objects also contribute (`Ext.wrap(row) { sb -> sb.append(q) }`),
  while a trailing assignment, declaration or `if` without `else` returns no value;
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
  constant or input-free fills beside a number add no input text
  (`val safe = "fixed"; template.format(safe, q.length)`). A resolved own
  String helper keeps its value inside a numeric scope
  (`q.length.run { trim(q) }` with an own `trim(String): String`);
  static Java/Kotlin formats also recognize an explicit or typed first Locale
  argument (`String.format(Locale.US, "%d", n)`), preserving the actual template
  when a String local or scope parameter shadows a Locale field;
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
as filled. A closure result that loses distinct input locations to the trace
cap stays `partial`, including `Ext.io({ big })` and `run { }`. Only a cut from
duplicate routes over at most eight input locations can be normalized to
`limited / source trace abstention` when included in a possible result. A local initialized from a string literal is a String, so
`var s = ""; s += q` concatenates where 1.7.0 recorded `compound assignment
operator dispatch unavailable`. Kotlin `x!!` is the value of `x` for literal key and IV
tracking, filled buffers and intent-target checks:
`SecretKeySpec(key!!.toByteArray(), ..)` with a literal key is reported,
`nextBytes(raw!!)` fills `raw`, and a component check on `nested!!` is
credited. With `--strict-coverage`, `limited` exits 3 (a `--fail-on`
threshold exits 4).

Reference dispatch also checks enclosing lexical class ancestry for inherited
Locale/kotlin values and preserves explicit cast targets through `!!`. Simple
positive `is` guards apply only to the same binding in the true arm. Scope-callback
reference facts use the same generic/component guards as element callbacks.
Project numeric names retain declaration-file identity instead of becoming
standard Int by spelling. Unknown dependency callbacks named run/async are not
assumed parameterless; traced ambiguous it reads can add a specific precision
reason even outside a modeled signature query. A no-op type hint without a
competing resolved helper stays silent. Repeated accumulator reference queries
share immutable result syntax; frame-dependent resolution is not retained across
queries. Typed destructuring that the bundled grammar cannot parse remains an
explicit parser execution gap, even when a Kotlin compiler accepts the source.

Standard String/Regex/numeric facts also retain declaration/import identity for
default-package names, content results, closure locals and overload signatures.
String and numeric spellings from source cannot suppress captured input. Nullable
numeric content is still scalar, while nullable callable receivers require a
separate proof. Explicit casts survive receiver queries. Positive `is` tests add
intersection evidence at receiver capture; a supertype test cannot erase a
source member, and a write or later guard cannot supply a stale type proof.
Companion values participate in implicit receiver lookup with private visibility
preserved. Callback shape checks reject a shadowed implicit receiver or stale
parameter type and clear their query-local memo on return. General smart-cast
control flow, exact reassignment recovery and anonymous callable scopes remain
bounded precision limits.

The trace cap now compares actual source locations before and after retention:
losing even one of eight locations stays `partial` when a duplicate route takes
the last retained slot. Raw and located forms of the same syntax node denote one
location. A duplicate-route-only cut can remain `limited`.

Ordinary escaped type names now share canonical inventory, lexical and owner
identities; root-package declarations in separate Kotlin files are retained.
Receiver proof preserves safe-cast and alias-expanded nullability, separately
from nullable content/reference compatibility. Template fallback cannot undo
that receiver abstention. String constructor hints respect source identity for
both inferred locals and direct receivers. Writes to local supertypes veto
stale implicit-head/callback proof even without an is-test; established final
standard declarations and literal-initialized final types remain usable.

Receiver proof now checks declared returns and qualified/copied member origins
before content hints. Module and companion values retain declaration context;
implicit callable String properties and cross-file private types cannot borrow
constructor/source identity. Inferred expression bodies use bounded type proof.
Explicit non-null scope entry/assertion uses a separate query policy and cache
key, including aliases, returns, members, copies, casts and modeled nullable
conversions. Standard callback hints reuse represented receiver/element origins.
Supertype spelling is canonicalized, and a later test cannot retype an earlier
copy. Property/module initialization and full generic/CFG inference remain
separate execution/precision limits.

## Remaining limits

A callee does not bind a lambda's parameters when it calls the lambda. Callee
following still does not bind a trailing lambda past a skipped defaulted formal
(`limited`). The declaration-only applicability and constructor-exclusion binder
can place that lambda at the final non-vararg formal; this does not add execution
of the skipped-default callee. Receiver
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
result, so a String transform on it is content (`fmt.let { it.format(d) }`;
coverage can be `checked` for a formatter field or object); a template a call returns is not filled
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

Source nominal identities remain distinct from modeled builtin names through
constructor facts and imported aliases, including default-package source classes.
Detached constructor proofs check declaration-site lexical values and visible
hierarchy/companion value heads before granting a class identity. A matching
callable property cannot become an unrelated source constructor proof.

Non-null standard receiver identity is retained at its declaration. Strict
receiver proofs do not borrow a detached initializer's caller names. Consumed
unknown receiver or pattern facts identify the actual affected call in precision
details without executing their initializers.

Detached constructor hints now require a represented ordinary no-argument
allocation; inaccessible or inapplicable constructors cannot replace companion
invocation. Competing outer receiver/companion values retain their lexical
visibility. Nullable imported aliases and nullable modeled receivers cannot
borrow positive String proof over a visible project extension. Optional
initializer hints do not add unconsumed receiver-identity details, and copied
default-package members retain their exact source owner. These remain bounded
static declaration proofs without initializer execution.

Receiver proof now re-queries the same origin with the non-null policy before
member precedence, including wrappers, casts, member navigation and copies.
Canonical aliases cover modeled String/Regex/numeric targets as well as other
standard receivers, preserving nullable expansion even for aliases named like
builtins. Nullable extension compatibility remains conservative through unknown
supertypes; inapplicable non-null/final-library controls stay separate.
Zero-argument constructor applicability includes defaults/varargs and explicit
zero-argument secondaries without executing them. Nested singleton object heads
remain visible, and opaque anonymous ownership cannot prove head absence.

Non-null extension receiver declarations are excluded from nullable competition
independently of the call receiver's modeled type. Known non-null supertype
spellings retain this distinction; nullable aliases and unknown generic receivers
still compete conservatively. Singleton head lookup includes inherited instance
members of the starting object, while ordinary static nested classes do not gain
an outer instance. Declared extension receivers may veto a conflicting imported
head without executing the extension. General extension execution remains bounded.
Ordinary companions with no competing head can be transparent to this proof;
inherited, named or unresolved companion heads remain conservative. Non-null
member precedence is established before an optional nullable-extension probe, so
an unused generic conversion does not add an unconsumed identity diagnostic.

Arity-compatible visible source callable heads now compete with constructor
spellings in ordinary/inherited receivers as well as declared extension receivers.
The constructor producer and retained known-value fallback preserve this
distinction. Unrelated same-name members do not suppress detached constructors;
private and inapplicable-arity controls retain their constructor facts. Getter
and setter receiver queries read the owning extension property's declaration.
Unused nullable generic conversions suppress optional type-parameter diagnostics,
while consuming queries still identify the affected call. Unknown external
extension receivers remain conservative, including for qualified standard heads;
this may add precision details without claiming complete SDK member knowledge.

Escaped generic identifiers retain one binding in String receiver applicability,
including Comparable argument checks. Parenthesized, nullable and definitely-non-null
receiver wrappers keep their declaration origin and nullability; unresolved shapes
cannot establish constructor-head absence. Explicit imported expression roots,
including object-member imports, do not become package namespaces. Same-file
aliases to modeled primitive parameters use exact declaration-origin Kotlin proofs.

Qualified source object values and ordinary uppercase callables retain source
identity instead of borrowing a library constructor name. Exact source namespaces,
private/arity/literal controls, default and vararg callables, and real nested
source allocations remain distinct. A kotlin expression import cannot supply a
standard array factory fact. Visible head and nullable queries keep unsupported
extension receivers conservative; unrelated unknown receivers no longer add a
checked builder candidate. Sixteen supported type wrappers reach their terminal.
Nullable/DNN exclusion applies only to queries carrying the proven nullable
subject. Inferred library-reference factory returns remain a documented precision
limit; a fixed-runtime control now has a diagnosed candidate rather than clearance
based on its qualified spelling.

Nominal library identity now checks the declaring file's source and import roots,
including parameters, locals, fields, cross-file returns and root-package classifier
collisions. Already proven standard-reference origins remain distinct from raw
type spellings, preserving genuine renamed imports. Qualified Java ordinary
callables use their own signature syntax. Kotlin named arguments and bounded known
String values retain primitive incompatibility when competing with a source
constructor. Capped builder receivers keep visible declarations competing and
anchor consumed uncertainty at the affected call; unrelated function receivers
remain excluded. These changes do not establish general overload ranking or
arbitrary inherited-object/instance-field execution.

Nested receiver scopes now retain ordered source-singleton dispatch owners for
builder member extensions, including qualified and parenthesized object receivers.
Nearer ordinary members, private declarations, nullable receivers and detached
helper bodies preserve their boundaries. Competing construction is excluded by
represented kind, accessibility, arity, labels or proven incompatibility before an
ordinary callable supplies a declared result; an exact String argument alone does
not defeat an applicable Any or nullable String constructor. Nonnull assertions
retain their explicit argument proof.

Package-level or source-member value imports do not establish absence of an
overlapping binary package classifier.
Unknown type roots withhold library identity and add precision at the consuming
String operation, with bounded declaration-origin details. Explicit standard
aliases and aliases resolved in their own uncontested declaration context remain
positive. Unknown String-extension receiver identities retain competition rather
than becoming incompatibility proof. These changes
do not add binary classpath inventory, general overload ranking or constructor
initializer execution.

Private nested nominal visibility and private constructor visibility keep their
different lexical boundaries. Incomplete default/trailing-lambda binding cannot
exclude a plausible construction. Source-object scope entry vetoes implicit and
inherited value shadows with bounded, restored query state; a proven modeled
Intent receiver can exclude unrelated source dispatch. Custom builder extension
argument-write approximations identify their effect limit at the consuming call,
so fixed-body candidates do not become checked through ownership alone.

The effect limit also follows explicit plain-`this` chains and identifies each
opaque inner contribution at its own call. Known builder members stay precise;
foreign supplied callback receivers keep their own effect identity. A shared
declaration-only applicability/exclusion binder places one trailing lambda at the final non-vararg parameter,
skipping defaults before it. Independent proven primitive/String conflicts still
exclude impossible construction, while Any, SAM and unknown finals remain
conservative.

String extension compatibility now distinguishes known standard/source classifiers
from unresolved imported/FQN identities, including binary aliases and Comparable
arguments. Alias proofs retain declaration context, a 16-link cap and the complete
selected name. Explicit Kotlin imports of represented default-package classifiers
reach the source-type fence before exact-spelling library identity. The obsolete
value-import inventory is removed; classifier import uncertainty remains intact.

Established Kotlin classifier imports precede weaker package aliases and
nominal declarations in the shared type selectors. Raw function/value imports
do not establish a TYPE identity: when a visible same-package classifier
competes and the imported classifier is not positively represented, consumers
retain unresolved identity and affected precision instead of affirming an SDK
spelling. The competitor may be an accessible Java/Kotlin JVM classifier or Kotlin
alias in another same-package or non-static wildcard-imported file; privacy and
Java accessibility remain separate, including implicitly public member types in
Java interfaces and annotation interfaces. This does not add general cross-language
execution. A function/value import cannot prove that an overlapping binary
classifier is absent. Stronger local/member/type-parameter
scopes remain in place. A losing package declaration cannot prove
incompatibility or hide a captured extension's effects. Selected represented
aliases expand in declaration context before exact-import or fully qualified SDK
acceptance, and library/model/declaration/resolved-receiver consumers agree on
standard, source-nominal or unresolved identity. An alias at an SDK FQN is not
automatically that SDK type. Legal qualified-name whitespace has the same identity
in declarations, casts and declared returns.

The cross-file default-package exception is limited to a matching dotless root
import, including a renamed root. A dotted SDK import no longer gains a false
source owner through a same-spelled default-package nested classifier. Opaque
builder contributions retain precision even without a represented extension.
Their reason uses declaration-context and selected-alias receiver proof rather
than collecting every alias with the same leaf name. Canonical attribution covers
existing builder supertypes and collection forms; every represented upper bound
must be accounted for, including constraints that prevent positive proof. Comments
are syntax trivia and do not enter that bound inventory or consume its allowance. A
function-typed bound cannot be dropped. Candidacy stays at receiver-root granularity,
with general generic substitution and overload selection outside that claim.
Attribution alias order is stable. Optional attribution is limited to 64 queries and 64 visited candidates
per analyzed file. Exhaustion uses the generic reason for unclassified contexts;
a bounded immutable syntax/receiver/scope ledger retains an already-proved custom
label on revisits without retaining Frames. Precision stays at the actual inner
contribution. Registered members keep their existing precise path.

#### Stored initialization and explicit extension coverage

Eligible named top-level Kotlin class/object property initializers now participate in bounded source flow together with ordered init blocks. Fresh construction state preserves stored values and receiver storage for later method analysis, while nonstored constructor parameters remain local to initialization. Custom getter results are not inferred from their backing initializer; unsupported initialization boundaries remain precise and execution caps remain partial. Cross-class runtime initialization order and general constructor-call argument mapping are not established.

A source-derived explicit project String-extension call whose receiver execution is unavailable now carries the existing receiver-flow precision reason at that call. It no longer silently leaves the affected native coverage checked. This is an honest bounded-model diagnostic, not execution of an extension body or recovery of its SQL finding. Safe constant and ordinary-call controls remain covered by their existing models.

Kotlin null literals now stay untainted. Indexed implicit-receiver property writes preserve their actual content data under the existing content-lambda model, including the HTML attributes-map case previously masked by erroneous null provenance. Bound maps and rebound receiver scopes retain their separate effects; this establishes source flow, not third-party escaping or exploitability.
