# Analysis coverage and partial diagnostics

APSA emits source candidates from bounded analysis. A checked file or an absent
finding does not prove runtime safety, installed reachability, or exploitability.
Coverage separates two shortfalls. An execution gap (an exhausted budget,
malformed input, a parse error or lossy adaptation, a skipped file, truncated
input) leaves part of the scope unexamined and stays `partial`, which makes the
audit incomplete. A precision limit (unknown dispatch, unresolved identity,
incomplete traces, a reduced language model) means everything in scope was
examined but the bounded model abstained on some paths; it is reported as
`limited`. `limited` does not make the audit incomplete unless strict coverage
(`scan --strict-coverage` or policy `strict_coverage = true`) is requested.
Aggregation precedence is `partial` > `limited` > `checked`. Neither state is a
safety claim.

## Native source flow

Java, Kotlin and Swift use bounded direct-call and field summaries. Recursion,
unknown receiver dispatch, ambiguous overloads, unavailable return/body flow and
inventory/trace/route budgets remain unresolved. They do not supply sanitizer
proof. Existing conservative scope is retained: every unresolved native-flow
reason applies to all native rules. Every reason has an explicit kind. A budget
reason (a resource cap on evaluations, depth, recursion, inventory, element or
target counts, traces or routes; for example `source trace budget` or
`native flow recursion budget`) is an execution gap and keeps that coverage
`partial`; a precision reason is an abstention of the bounded model and makes
coverage `limited` when nothing else left it partial. A trace keeps the kind of
its cut through later calls and sinks: a value the model abstained on (for
example `constructor field mapping unavailable`) records
`source trace abstention` when passed to a call and stays `limited`, while a
trace cut by the trace cap (origins dropped when values merge, including at a
sink) records `source trace budget` and stays `partial`. Loss of more than eight
distinct input locations is identified before truncation and remains a budget
inside a closure result too. A duplicate-route-only cut in a possible closure
result can instead record `source trace abstention`: the unresolved callee may
never return it, and an own call's field-round duplicates would otherwise make
the idiom `partial`. This normalization also applies to duplicate routes in a
`let`/`run`/`with`/`use` result, without demoting genuine distinct-source loss.
Field summaries whose sources and contents stopped changing while derived trace
identities still change record the precision reason
`field summary fixed point unresolved`; contents still changing at the round cap
record the budget reason `field summary fixed-point budget`. Unknown calls
re-derive trace origins each round, so a field can accumulate duplicate traces
of the same source; whether those reach the trace cap before the round cap
decides the kind, so the classification can depend on the round cap. A trace
cap that is hit is a budget gap outside that duplicate-route exception; a round cap that is hit is a budget gap
unless the field contents stopped changing in the last round. An unaffected file's empty
diagnostic list does not make its rules globally complete.

Objective-C `.m` files are examined only by the `OBJC-*` rules, through a
reduced model: they are `limited` when every observed function was analyzed and
`partial` when a function inside `#if`/`#ifdef`/`#elif`/`#else`, a parse error
or a lossy adaptation was skipped, or a file was dropped before analysis.
Objective-C++ `.mm` files are never examined, so any `.mm` file leaves the
`OBJC-*` rules `partial`. Functions hidden by unexpanded macros are never
observed; that remains a precision limit, and `function_inventory_complete`
stays false. `AST-*` rules never examine Objective-C or Objective-C++: beside
Java, Kotlin or Swift sources they are `partial`, and for an
Objective-C-family-only source set they are `not-run` (Android-only rules are
`not-applicable` for iOS-only sources).

`AST-CRYPTO-ECB`, `AST-CRYPTO-WEAK-CIPHER` and `AST-SQL-CONCAT` are not
implemented for Swift. Swift alone leaves them `not-run`. Beside Java or Kotlin
sources the Swift files are still parsed and examined by the AST engine, so the
missing Swift model is a precision limit: these rules are `limited` (with a note)
where they would otherwise be `checked`, and stay `partial` for any execution
gap. Project-declared SQL sinks examine Swift for their exact specifications
only, which likewise leaves `AST-SQL-CONCAT` `limited`.

A recognized source file dropped before parsing (byte or node budget, an
unavailable grammar, a parser failure) is an execution gap even when no other
file parsed: the rules stay `partial`, never `not-run`, and its file row stays
`skipped`, which also counts as incomplete. Unsupported-language files alone
leave AST rules `not-run`.

`source_analysis.native_flow.partial_details` records the reason, file, line,
column, call name where available, uncertainty category, `kind` (`budget` or
`precision`), and conservative rule scope. `budget_reasons` and
`precision_reasons` split `reasons`; the diagnostic `state` stays `partial`
whenever any reason exists. Global uncertainty has an analysis scope and no invented file or call.
Records are deduplicated, sorted and limited to 256; the lexicographically first
records are retained when the limit is reached. `partial_details_truncated`
means additional diagnostic locations are unknown. It never clears the reasons
or changes partial or limited coverage. File metrics include local/global reasons and a
diagnostic completeness flag; this is explanatory scope, not a claim that only
those files or rules can be affected.

The native call limits remain eight levels, 1,024 evaluations, 4,096 inventoried
callables and four field-summary rounds. Parser, trace, route and finding limits
apply independently. Closures, lifecycle callbacks and dynamic dispatch are not
a complete application call graph.

Content-closure value classification shares a 65,536-unit work limit across its
nested contexts. Compatible graphs are indexed by frame identity and represented
node span; unrelated sibling callbacks are not scanned. Candidate context queries
also consume classification work. An exhausted limit records `closure value classification budget`
as a budget reason and leaves native-rule coverage `partial`.

Kotlin overload hints use known literal, conversion and declared return kinds,
retained local kinds, and labels/arity for explicitly modeled operations. They
distinguish known primitive operands and integral literal adaptation, but are
not a compiler type system. Non-stdlib type qualifiers remain distinct in
these hints; unknown types and arbitrary external overloads are not proven.
Qualified generic roots and lexical type bindings are preserved. Visible source
aliases are followed in their declaring files for at most 16 alias declarations;
cycles, conflicting visible aliases and unproven type-parameter roots record
`callable argument type identity unresolved`. Alias expansion establishes nominal
roots, not a general generic-substitution or overload-resolution system.
Reference argument types are resolved at their represented declarations, rather
than reinterpreting parameter/field type names under a later local class. The
declaration indexes store immutable syntax per analysis; call-specific values
are not cached there. Nullable Array arguments record the same precision reason;
smart casts and arbitrary generic substitutions are not established by these
nominal facts. Numeric hints keep their eight-level depth bound, reuse computed
operand kinds and abstain with a precision reason on an unproven numeric
signature instead of borrowing a competing helper's return kind. Type-hint
queries do not evaluate scalar provenance to fill missing operand kinds.
The same restriction applies when numeric overloads are classified as content
or scalar. A scalar local with an unproven operand kind can still produce a
conservative content finding; the classification-only signature limit is
visible even when ordinary re-read diagnostics are muted. Receiver-kind facts
are shared only within one query and frame, including nested queries. Successful
facts are independent of remaining depth; unknown facts retain their query depth.
They do not persist across calls. An unused bounded-out type hint does not limit
ordinary initializer coverage; a dispatch consumer records its uncertainty.
Lambda-body, loop, catch, when and destructuring declarations block farther
same-named bindings. Loop variables are visible only in their bodies, and when
subjects only after their initializers. Known element callbacks bind implicit it;
simple declared standard containers retain their element's declaration context.
Opaque container aliases and inferred element types can remain unproven.
Unshadowed top-level repeat binds an Int index. Proven parameterless or receiver
callbacks preserve an outer it. Other call-argument lambdas with an implicit
parameter of unproven identity block farther type facts; conservative findings
can remain, with an explicit precision reason when that ambiguity is consumed.
Callback reference facts distinguish element, accumulator and index positions.
Accumulator initialization is used only for an identity-returning callback without
explicit type arguments. A standard collection factory's single explicit element
type is checked at its lexical origin, including nullability. Component patterns
and other explicit generic instantiation need independent facts. Represented cast target spellings and safe-cast nullability
are retained by reference-signature queries.
Discarded lambda parameters do not bind implicit it, and plain
constructor parameters are not instance fields. Qualified own/project member
facts use represented declarations; unavailable, inherited, static/companion or
untyped member origins may remain limited. A package/type qualifier does not
prove an instance-field selection. Reference signature queries preserve branch
results and share declaration facts within a query. Unknown result expressions,
including unresolved nullable expressions and deep initializer aliases, abstain
with callable argument type identity unresolved. This may conservatively retain
a helper flow when the real operation is standard; no general Kotlin expression
type inference is claimed. The reference-query depth bound is sixteen.
Known Locale constants, constructors and selected static factories, and standard
Array construction retain nominal reference kinds without treating a value or
project type shadow as the standard class. This is a small library model, not
general SDK return typing.
Standard class/package heads also exclude represented values supplied by implicit
receivers, including inherited fields. Project return spellings are resolved in
the declaring file; incomplete ancestry cannot prove that a name is absent.
The check includes enclosing lexical classes and their source ancestry, excluding
inaccessible private fields. Cast subjects retain their target spelling; a simple
positive `is` test narrows the same binding only in its true arm. This is not a
general Kotlin smart-cast engine. Cast-preserving reference queries also traverse
parentheses and `!!` without discarding an explicit widening cast.
Numeric declaration and return hints require standard nominal identity before
using numeric precedence. A source class named `Int` or an imported project alias
does not become a standard number by its leaf name. Unknown aliases, type
parameters and nullable numeric declarations can remain visibly conservative.
Numeric dispatch distinguishes an absent receiver from a represented receiver
whose kind is unproven. Consuming the latter records a precision limit rather than
borrowing a competing helper's type, including after a bounded-out initializer.
An unused hint with no competing resolved helper does not itself add that limit.
Receiver-bearing names such as `run` or `async` do not prove a parameterless
callback on an unknown dependency. Resolved source callback signatures decide
their shape; established standard receiver facts can also preserve an outer it.
Unknown callback bindings can record the type-identity precision reason on a
traced it read even without a later modeled overload query. Other unresolved-call
reasons may already limit such code; this is not exact dependency/SAM typing.
Frame-dependent callback decisions remain query-local. Immutable accumulator
result-node inventories are shared outside classification-budgeted walks; a
budget-cut inventory is not retained as complete. Work guards cover both repeated
fold consumers and repeated unknown-callback reads.
The receiver-tower disclosure covers known numeric/String alternatives, including
shared operation names and direct calls. Other incompatible or unknown receiver
types are not a complete receiver-tower model. Covered alternatives record
unresolved callable identity or argument signature. This model is not a Kotlin compiler.

Project extension visibility checks package/import, owner and lexical access;
incomplete receiver binding records `Kotlin project extension receiver flow unavailable`
and leaves coverage `limited` once a String receiver is established. Known compatible
String supertypes include CharSequence, Any, Comparable and JVM Serializable;
fixed incompatible Comparable arguments do not veto the standard String shortcut.
Opaque alias generic arguments remain conservative and `limited`. Unknown DSL receiver signatures with explicit
lambda parameters are not fully modeled. The documented branching-mix content
limit also applies to supplied writes; a nested callback returning only a bare
call result does not become new content merely because its closure carries traces.

## Kotlin type origins and retained source locations

Standard String, Regex and numeric facts now retain lexical declaration/import
identity, including source types with an unqualified default-package name.
Content-result and closure-local numeric classification checks the declaring
type before discarding input. Nullable standard numeric content remains scalar;
a nullable receiver still needs its own callable proof. The String signature
shortcut is used only after an immutable source-name/import inventory excludes
a shadow, preserving bounded lookup work in deep builder closures. A standard
typealias can retain its proven standard identity; unrelated aliases or lexical
type parameters cannot erase inherited overloads.

Kotlin receiver queries preserve explicit cast targets. Simple positive
`is` tests contribute intersection evidence at the receiver expression's
capture position: a supertype/marker test cannot erase an existing source type,
and a later test cannot retroactively narrow an already captured receiver.
A write between a test and that capture prevents the test from proving a
standard head. This is bounded lexical evidence, not general control-flow,
assignability or smart-cast analysis; reassignment can still produce a
conservative input result with a precision reason.

Class and inherited companion values participate in implicit head checks with
private visibility retained. Callback arity checks use the same implicit
receiver evidence; a local receiver declaration also blocks an unrelated
parameter's old type. Reentrant callback-shape queries share a per-query memo
that is cleared when that query returns, including cycles. No mutable Frame
facts are retained across queries. Unknown dependency callbacks and anonymous
callable scopes remain explicit precision limits.

A capped source trace compares source locations before and after retention,
rather than just counting unique locations. Dropping one of eight locations
still stays `partial` if a duplicate route occupies the final retained slot.
Raw and located forms of the same syntax node count as one source location;
duplicate-route-only collapse can remain `limited`.

Ordinary escaped Kotlin type identifiers are canonicalized at nominal inventory,
owner and lexical lookup boundaries, including aliases and type parameters.
Source bytes and offsets remain intact; unusual escaped names remain outside
this ordinary-identifier support. Same root-package Kotlin declarations in
different files can retain one source identity.

Modeled receiver proof preserves safe-cast nullability and alias-expanded
nullability. Its nonnullable policy is separate from reference-signature
compatibility and nullable scalar-content classification. Template-value flow
can still retain nullable text, while the receiver fallback checks declaration
identity and casts before granting nonnullable String dispatch. Represented
constructors named String use source/import identity rather than a builtin
name hint, including inferred locals and direct receiver expressions.

A local write can invalidate a supertype-based head or callback-shape proof
even without an is-test. The structural write index is queried between the
declaration and the receiver's capture, including copied receiver origins.
Proven final standard declarations and literal-initialized final types retain
their absence proof after writes. This is conservative abstention rather than
exact reassignment recovery. Unknown dependency/private callback controls may
still retain input with their existing explicit precision/budget diagnostics.

Positive receiver hints now validate declared returns and represented member
origins, including copied member reads. An explicit nullable return cannot fall
back to a content-only String header. Inferred expression-body returns use a
bounded type query with formal type declarations and no borrowed argument
values. Nonnullable String concatenation is established from a proven String
left operand.

Expression-return queries select the declaring function for owner and lexical
resolution. Caller parameters, fields and retained node facts are isolated and
restored even if a query fails. Reads inside this query use retained facts;
they do not execute calls or initialize fields. An unresolved identifier in an
inferred return, such as an unrepresented inherited field, retains the callable
type-identity precision reason when consumed as a receiver. A retained text
category cannot override a rejected nullable call return; a fallback project
return proof also requires the retained text value, so an uncertain competing
numeric dispatch is not replaced by a helper declaration alone. Represented
qualified calls can use a bounded receiver type fact without executing it.

Function-bound type queries require the expression's lexical function to match
the active context. Detached initializer identifiers use fresh declaration
facts; their calls and other unrepresented expressions abstain before library
name hints. A resolver without an active function returns an unknown target,
never an invented root owner. When such an inferred initializer or an untyped
callback receiver is consumed, an unresolved origin keeps the callable
type-identity precision reason. A proven nullable origin does not gain that
reason merely because its nonnullable query was rejected. Unlisted callbacks
such as runningFoldIndexed/scanIndexed can therefore remain conservative with
a visible type-identity limitation.

Receiver facts retain qualified source/import identity at their declaration
origin. An ambiguous bare nominal or a root source spelling that cannot identify
the same owner at the use site is not rebound in the caller's namespace.
Receiver-proof fallbacks read retained values only, check declared return
identity first and never visit an unobserved initializer. Represented module
identifiers are not labeled missing lexical identities; a separate actual
module value-flow inventory gap can still remain limited.

Module-value candidates retain their declaring source, import/visibility
context and type spelling; companion member lookup retains its own property
declaration. Ordinary companions without supertypes can continue lexical type
lookup after checking their own declarations. A named companion matching the
type root or an inherited/unavailable companion still blocks absence proof.
Unqualified String constructor hints also consult implicit receiver value heads;
a callable property named String cannot become the builtin constructor.
Cross-file private nominal declarations are excluded, while same-file private
types remain source identities. Supertype spellings use the same supported
ordinary-identifier canonicalization.

Nullable receiver queries keep a separate policy for explicit non-null syntax
(`?.` scope entry or `!!` assertion). Query memo keys include that policy, so a
nullable rejection and a non-null proof do not reuse each other's entry.
The policy applies to return/member/copy/cast facts, alias expansion and the
modeled toIntOrNull/toLongOrNull results; scalar-content/reference compatibility
remains separate. Standard scope and collection callback type hints retain
their receiver, initial-value or element declaration origin where represented.
Explicit generic/component callback forms remain bounded abstentions.
A later test cannot retroactively narrow an earlier copied receiver.

A Kotlin safe member access has a nullable result even if its receiver is
already nonnullable. Safe-call and safe-property results therefore require a
consuming `?.` scope entry or `!!` assertion before supplying a nonnullable
receiver kind. This includes `toString`, conversions, scalar properties and
declared project returns. Callback element/accumulator proof uses original
parameter positions, retaining discarded `_` slots in indexed and fold calls.

Type-origin queries do not execute property/module initialization or prove
general CFG, generic assignability or unavailable dependency behavior.
Represented constructors with default arguments and unresolved aggregate
effects can retain explicit precision limits. The existing private callback and
post-write object-alias conservative results are not claimed exact.

Detached initializer queries may retain a unique source constructor's nominal identity
from declaration syntax when no value, import or project callable competes with it.
Only a concrete ordinary source class with a represented accessible constructor
that accepts no arguments can supply this detached fact. Defaulted/vararg primary
parameters and explicit zero-argument secondary constructors are checked from
syntax, without evaluating defaults. Private/protected candidates outside their
declaring class are excluded; an accessible secondary may still prove allocation.
Singleton, abstract/interface and unproven signatures abstain. The fact does not
recover field state. Enclosing inner receivers, outer companions and singleton
object members participate in competing-head checks; an ordinary outer instance
member is not made visible to a static nested class. Opaque anonymous ownership
blocks a positive absence proof.

Source/import nominal facts that collide with modeled builtin names retain their
source distinction, including root-package imports and aliases. Imported aliases
grant modeled kinds only after canonical library identity is established. A
detached constructor fact also requires no lexical value or visible inherited or
companion value competing with its head name. These checks preserve nominal type
identity; they do not execute the initializer or recover its field state.

Known non-null standard receiver identities are checked at the declaration, so a
caller's same-named class cannot replace a represented library type. Detached
strict String proofs use declaration facts with an empty frame. Constructor and
project-call results outside that context may remain unknown. If an unanchored receiver withholds a modeled text/numeric result hint, or a
builder consumes an unrepresented initializer pattern type, the precision
detail identifies the affected call. An unrelated diagnostic elsewhere does not
justify a missing flow.

Imported typealiases grant modeled and other standard receiver kinds only through
their declaring source, before the spelling is split by modeled name. An
unresolved alias is not an invented nominal class. Receiver queries preserve the
same origin's non-null policy through parentheses, casts, members and inferred
copies. A nullable receiver cannot borrow non-null member precedence when a
represented visible project extension may compete with toString. Unknown
nullable supertype/alias compatibility abstains; proven non-null extensions and
distinct final library receiver types are excluded. Full generic assignability
is not modeled. Standard nullable toString and explicit safe/asserted calls keep
their separate controls. Default-package source identity markers
also survive copied member lookup without rebinding in the caller's namespace.
Optional initializer hint queries suppress unconsumed receiver-identity details;
later modeled consumers still record the actual affected call. Existing value
ownership/effect diagnostics remain independent of those optional hints.

Nullable extension competition checks the extension declaration's own non-null
identity against the known standard/source type universe, independently of
compatibility with the actual receiver. Nullable aliases and unknown generic
receivers do not establish this exclusion. Non-null member precedence is queried
first, so an unused generic nullable extension cannot add a diagnostic to an
already proven non-null conversion.

The singleton instance-member head search includes its represented ancestry;
ordinary static nested classes still do not acquire an outer instance. An ordinary
companion with no matching value/type/callable or inherited receiver can be
transparent for a head proof. Named, inherited and unknown competing companion
heads remain conservative. Declared Kotlin extension-function receivers and
extension-property accessor receivers participate in the head query. A represented
source value or arity-compatible visible function can veto an imported constructor
spelling. Unavailable external, generic or collection receiver definitions may
also conservatively withhold true standard facts, including qualified heads. This
can add precision details within that extension while retaining its tainted sink;
it is not a complete SDK member inventory. General extension execution and
field-state recovery remain bounded. A missed represented extension result needs
the affected callable diagnostic, not just a reason at an earlier assignment.

Constructor queries collect represented callable competitors only in query-local
node-ID sets; they do not retain frames or execute the function. An unrelated
same-name member elsewhere does not globally suppress a detached source
constructor. Local/top-level competitors require declaration-site language,
arity and visibility. A known callable prevents a constructor fact at its
producer. Unknown ownership alone may retain a possible allocation for existing
field provenance, but known-value library queries recheck a retained
constructor-like hint against the expression's head before accepting it. Consumed
uncertainty identifies that call; optional initializer hints suppress the detail.
The generic type-parameter identity probe follows the same optional-hint rule.

Callable names use the same normalized spelling for escaped declarations and
calls. Arity checks count required parameters before accepting a vararg function;
the vararg alone does not make earlier mandatory parameters optional. A literal
String excludes a candidate whose corresponding parameter has a proven non-null
Kotlin primitive type. Fixed positional parameters and remaining unnamed literal
vararg elements are compared with their parameter or element type; elements are
not mapped to trailing defaulted parameters. Spread/unknown arguments do not
establish a literal conflict. Other compatibility remains conservative; this is
not full overload resolution.
Primitive-looking generic parameters and aliases are not primitive proof.
Finite primitive targets also use non-null Kotlin identity proof at the
parameter declaration, including same-file aliases to modeled primitives and
imported renamed aliases. The whole
applicability query, including modeled-name classification, is optional: it
suppresses its own unused identity uncertainty and restores depth after failure.

Visible project extension heads also participate when their represented implicit
receiver is compatible, including source instances and known String or numeric
scope receivers. Unrelated source receiver types do not compete. This lookup
records declaration identities without running extension bodies. Retained
constructor hints check the complete qualified expression spelling, and a value
at a qualified head's root prevents treating that chain as a package allocation,
including visible module values and imported value aliases. An alias-expanded
extension candidate must match the imported callable's full identity; an import
alias for a class does not also alias an unrelated same-leaf extension function.
Same-file value import aliases use the same exact imported identity as cross-file
aliases. Same-file private declarations remain visible; cross-file private values
do not become package-looking expression roots.
An explicitly imported qualified root cannot silently stand for the written
package prefix, including imports of object-member values. Represented source
types retain their own nested-type lookup. This veto does not execute imported
values or claim their runtime ownership.
Supported escaped generic names use canonical declaration/use identities in the
String path, including Comparable arguments. Bounded receiver-wrapper lookup
unwraps parentheses, nullable types and definitely-non-null intersections while
preserving declaration origin and outer nullability. Queries that explicitly
supply a proven nullable subject exclude a proven bare definitely-non-null
receiver. Other head queries can remain conservative; this is not a whole-program
nullable-overload proof. The unwrap bound accepts 16 wrappers when the resulting
terminal is represented. Unsupported or capped shapes compete in visible head
and nullable queries rather than establishing head absence. A capped receiver can
also compete in builder lookup only when its source declaration is visible to the
caller. Consuming that unknown compatibility records precision at the builder
call. Uncapped unsupported receiver shapes remain excluded from that builder
lookup, preserving unrelated function-receiver controls.
The source-type namespace exception checks the complete written qualifier.
Represented ordinary qualified source callables can veto uppercase allocation
heuristics using declaration visibility, arity, labels and literal incompatibility,
without executing their bodies. This includes exact package-qualified callables;
it does not add general companion or instance-field execution. Actual nested
source allocations retain their source owner identity, never a library identity
borrowed from an alias spelling. Existing implicit-receiver uncertainty still
takes precedence. Declared return facts remain available before the retained-value
fallback; inferred library-reference returns through ordinary source factories
can remain diagnosed conservative candidates. A fresh fixed-runtime factory
control loses its earlier spelling-based apparent clearance under this stricter
rule. That is a precision limit, not restored factory-return inference.
Qualified Kotlin array factories check the complete call head, so an object-member
value imported as kotlin cannot become the standard kotlin.Array factory.
Nominal library facts check qualified source/import roots in the type declaration's
own context, including parameter, local, field and cross-file return declarations.
A represented source classifier can textually collide with a library FQN without
becoming that library type. An identity already proven by the standard-reference
query retains its origin; its canonical FQN is not reparsed as a new type spelling
under an unrelated expression import. This preserves genuine renamed imports.
Qualified ordinary callables use their language's represented signature syntax;
the fixed-arity Java method path does not read Kotlin parameter nodes. Kotlin
String-to-primitive incompatibility binds named arguments to declaration names,
preserving positional/default/vararg distinctions. Its qualified-call query can
also read explicit declaration/cast identities and canonical inferred ordinary-local
facts from the actual caller frame, without resolving or reevaluating argument
expressions. Nullable String nominal facts can disprove a nonnull primitive
parameter independently of receiver-dispatch nullability. This shallow check runs
only after proving the relevant primitive parameter and does not restart a generic
type-inference query. Unknown applicability preserves possible source construction
with precision at the competing call; it does not prove the sibling's declared
return or a library identity. A represented ordinary callable is selected only
after excluding its competing construction. Bounded exclusions cover ordinary
interfaces, inaccessible private nominal declarations or primary constructors,
complete implicit/primary arity and labels, and proven primitive incompatibility.
Private nested declarations are checked in their declaring owner's AST scope;
top-level private declarations remain source-file scoped. These enclosing-gate
queries stop after 64 nodes. For declaration-only applicability and constructor
exclusion with a supported fixed signature, one syntactic
trailing lambda binds to the final non-vararg parameter, skipping preceding
defaults. This proof does not add callee following through skipped defaults.
The binder does not search backward past a final vararg. Independent
String or literal-lambda incompatibility with a proven nonnull primitive/String
parameter can exclude construction; lambdas are not blanket-excluded from Any,
SAM interfaces or unknown types. A String argument does not by itself
exclude an applicable Any or nullable String constructor. Secondary, companion,
variadic and otherwise unmodeled construction remains unknown. Explicit `!!`
syntax retains its nonnull proof before argument wrappers are removed.
General vararg/constructor ranking remains unknown. Java method invocations are
never allocations merely because their names start uppercase; explicit new
expressions keep their constructor path. Unresolved Java vararg dispatch can still
miss flow with precision at the invocation. This is not general overload ranking
or compiler-wide applicability inference. Capitalized source-object value calls,
including member and project-extension `invoke`, retain preexisting diagnosed
dispatch limits; their nominal approximations are not proof of allocation or a
declared library result. This does not add general value-call execution.
In Kotlin TYPE positions, neither package values nor uniquely represented nominal
members can prove that an overlapping binary package classifier is absent.
Such unresolved imports withhold library identity even in the no-dependency
twin. A consumed String-overload uncertainty is recorded at the affected call;
up to eight declaration-origin locations supplement that detail. Optional queries
do not emit this consumed uncertainty. Expression roots keep their stricter
value-shadow rules. This distinction does not execute imported values.
An explicit Kotlin import of a dotless default-package root can identify its
represented nested classifiers across source files. That exception matches the
current owner to the resolved imported root plus the written remainder; a dotted
SDK import does not qualify merely because an import exists. The root is checked before an exact qualified
spelling supplies a library fact; Java/Swift and unimported/private source gates
remain separate. Raw import syntax does not establish a classifier kind or prove
that a represented function/value excludes an overlapping binary classifier.
Represented builder extension candidates now check
declaration visibility as capped candidates do; a supplied unrelated source class
named StringBuilder does not establish the standard builder receiver identity.
Active source-object scopes retain ordered dispatch owners across nested builders
and receiver scopes, including parenthesized and qualified object expressions.
Explicit singleton types and at most eight immutable-local alias links can supply
an owner. Proven final scalars can exclude an owner without establishing one.
Nearer applicable source members compete in receiver order for object-owned
member-extension candidates. Known builder members and top-level extensions keep
separate, narrower dispatch approximations. A compatible custom builder extension
is not proof of its write effects: treating its arguments as receiver writes
records precision at that actual call, including fixed-body candidates.
A priority-aware receiver-root proof can establish a represented
project-extension candidate for the custom-extension reason. Losing aliases from
other scopes cannot re-enter that proof through a leaf-name union. A dedicated
canonical table covers the already modeled builder receivers and their writable
supertypes, including Appendable and collection receivers; bounded type parameters
use their declaration-context constraints. Every represented upper bound must be
accounted for; syntax comments are excluded from this inventory and its bound
allowance. Function-typed or unsupported constraints cannot be silently dropped
to obtain positive builder proof. Root-level candidacy does not establish general
generic argument substitution or overload selection. This adds attribution proof,
not new builder execution. Callable aliases are visited in stable order in attribution
mode before its allowance is consumed; ordinary dispatch ordering is separate.
Other opaque or unmodeled contributions use a generic builder-chain effect limit;
absence of a represented extension does not prove the effects. This optional label
query has per-file allowances of 64 queries and 64 visited callable candidates.
Exhaustion selects the generic reason for an unclassified context while preserving
precision at the actual contribution; it does not claim resolved effects.
A previously proved custom label is retained on revisits of the same immutable
syntax, receiver, function and scope profile. This metadata ledger has at most one
entry per successful optional query and retains no Frame or mutable effect state.
Temporary query mode and type-hint depth restore after every query, including
failure. This distinction chooses the reason, not whether precision is recorded.
This also covers plain `this` and recognized implicit chains: each opaque link
gets its own call location, while registered outer builder members remain precise.
Effect routing and diagnostics share the same supplied-object identity check;
a foreign callback parameter cannot borrow an enclosing builder's receiver type.
Labeled builder receivers retain a separate preexisting flow limit and are not
covered by the plain-`this` chain repair.
Queries inspect at
most 64 active scope facts and check their source, function and lexical span;
unknown ownership stays conservative at a consuming builder call. Scope exit and
detached function inference restore the caller state. Unrelated objects,
shadowing local, implicit-receiver and inherited member values, and inaccessible
private members do not gain that owner. Expression-head vetoes use at most eight
active queries, restore flags in `finally`, and can reuse proven enclosing object
facts. Scalar probes are optional type queries; they do not emit unconsumed type
uncertainty. An exact modeled Intent declaration can exclude an unrelated source
dispatch owner without establishing a source object or complete SDK inventory.
This path does not infer arbitrary instance or factory receiver ownership.
Type-parameter extension receivers use their represented bounds without a
redundant library-identity probe that would diagnose an already rejected candidate.
Head queries follow inline/where bounds and parameter chains for at most 16 links,
resolving concrete aliases at their declaration. Unknown/cyclic/capped bounds
continue to compete. Only proven incompatibility rejects a bound: standard
receiver profiles come from established identities, and source nonintersection
requires a complete represented ancestry. String keeps its separate variance
checks. These declaration queries neither execute callees nor retain frames.
For String extension receivers, unresolved classifier identity retains competition;
it is not evidence of incompatibility. Intersection bounds preserve a separately
proven incompatibility, while a proven alternative can establish compatibility.
Query-local origin collectors are restored before consuming diagnostics are recorded.
Unsupported imported or fully qualified classifiers, including binary typealiases,
remain unknown. A pure declaration proof distinguishes established standard and
source-nominal identities from unresolved names. Alias selection preserves its
declaration context and stops after 16 links; ambiguity, cycles, and a qualified
selection through only an alias prefix do not prove incompatibility. The same
distinction applies to Comparable's argument. These proofs emit no diagnostics
or callee effects themselves.
An established imported Kotlin classifier precedes a weaker package-level
classifier; the losing package declaration cannot re-enter through alias
selection. Import syntax also names functions and values. If a visible
same-package or applicable non-static wildcard-imported class or alias competes
with an import whose classifier is not positively represented, type identity
stays unresolved rather than affirming either the source nominal or an SDK spelling.
This includes admitted Java/Kotlin JVM classifiers and Kotlin aliases in another
file, with Java accessibility and file-private visibility preserved. Accessible
member types include represented implicitly public nested types of Java interfaces
and annotation interfaces. Recognizing
a competitor adds no general cross-language callee execution. A represented
function/value is not proof that a binary classifier with that FQN is absent.
Consumers retain affected precision; pure type queries do not execute imported
values or emit that consumed diagnostic. Function-local, class-member and
type-parameter bindings retain their stronger lexical scope, and unknown
ancestry remains conservative. Expression/value import resolution is separate.
Represented selected aliases are expanded in declaration context before accepting
an exact imported or fully qualified SDK spelling. TYPE presence alone is not
SDK identity: an alias at android.net.Uri may denote a source nominal. Library,
external-model, declaration and retained-receiver queries preserve the same
standard/source/unknown distinction instead of reintroducing the raw import.
Legal whitespace in qualified type names is normalized consistently before alias
lookup and fallback, including declaration, cast and declared-return consumers.
CharSequence does not acquire Comparable or Serializable as known supertypes.
Numeric Comparable argument compatibility remains conservative, so an incompatible
generic extension can withhold a constructor fact. Some generic Number parameters
and alias-expanded source bounds still produce diagnosed conservative candidates,
without affirmative standard-library facts. Preexisting false positives also occur
when a locally constructed receiver's String result
is consumed inside nested numeric or CharSequence scopes, including controls
without an extension. Some of those controls remain checked; these constructor
head changes do not establish complete project-instance or receiver-tower flow.

Optional type hints suppress only unconsumed callable-identity details, including
numeric queries. They preserve execution and source-trace budget diagnostics;
consumed uncertainty still identifies the affected call. The retained-constructor
check applies to all consumers of known-value type facts. An unavailable external
implicit receiver can therefore leave a source allocation such as `Holder()`
visibly `limited`, even when its later String member has no input. This is a
conservative identity limit rather than evidence of a tainted member.

## Hybrid source and compiled artifacts

JS, TS and Dart use token/block flow, not full compiler semantics. Analysis covers
observed argument/return flows; it does not prove sanitizers, native bridge
implementations, callbacks, lifecycle dispatch or runtime execution.

Text `.jsbundle` files are accepted as JavaScript source. A `.bundle` file is
eligible only when it is UTF-8 text without binary control bytes and has an exact
recognized name (`index.android.bundle`, `index.ios.bundle`, `main.bundle`) or a
Metro `__d(...)`/`__r(...)` marker. Recognition is a source-input heuristic, not a
proof of a valid complete React Native bundle. Unknown `.bundle` files and
non-text input are recorded as skipped.

Hermes execution/delta header signatures identify bytecode presence only; no
instructions, version compatibility or string tables are analyzed. The signatures
come from the upstream [Hermes bytecode format](https://github.com/facebook/hermes/blob/main/include/hermes/BCGen/HBC/BytecodeFileFormat.h).
`.hbc`/`.hermes` names are bytecode candidates, not validated bytecode.
`libapp.so` and `App.framework/App` names indicate Flutter AOT candidates;
recognized Flutter snapshot names indicate compiled-content candidates. These
names do not establish artifact validity, installed reachability or even the
actual compiled format. No compiled artifact is admitted to text source flow.

`hybrid_inputs` inventory records distinguish source available from skipped
content and include representation, recognition basis and skipped reason.
`hybrid_analysis.files` adds the actual `analysis_state` (`analyzed` or `skipped`).
`analyzed` means content was admitted to bounded source flow; such a file and the
hybrid rule coverage are `limited`, and `flow_state` records whether modeling was
incomplete. Hybrid coverage stays `partial` when any hybrid file was skipped, a
hybrid flow budget was reached, or the input observations or inventory were
truncated or incomplete. Framework
summaries count observed files, analyzed text files, skipped files and observed
representations. Presence of Hermes/AOT files never counts as analyzed text.

Input observations retain at most 256 records. Truncation or incomplete source
enumeration makes additional framework presence unknown. Source staging preserves
recognized compiled names as metadata without copying or opening compiled bytes.
These observations are not part of a source-content fingerprint and must not
promote fingerprint completeness. Existing exclusions and no-symlink rules apply.

Text bundles share ordinary staging/source limits and the hybrid limits: 2 MiB
per source, 16 MiB total, 100,000 tokens per file, 2,000 functions, 300,000 flow
operations and six summary rounds. A skipped or truncated file cannot establish
absence of a candidate.

## Credential text admission

Known-format credential matching has a separate bounded text channel. Source
and packaged text can be inspected without admitting credential-only
`.properties`, `.strings`, `.pem`, `.key` or `.xcconfig` files to general source flow.
Private local environment files such as `.env` are not admitted. Eligible
APK/IPA text resources, including admitted JavaScript bundles in those packages,
use `PACKAGED-CREDENTIAL-TEXT`. Credential candidates from other admitted
representations (source folders, source ZIPs, AABs and `.app` folders) use
`SOURCE-HARDCODED-SECRET`. Neither route makes compiled source rules analyzed.
Only strict UTF-8 (optional BOM) and BOM-marked UTF-16 plaintext are decoded.
Binary plists, other binary content, unsupported encodings, skipped files and
exhausted limits remain unknown or partial. A filename alone proves no content.

The channel shares existing per-file, total-size and no-symlink input limits.
Reports contain aggregate coverage metadata and masked candidates, never the
collected plaintext channel. Credential values use a fixed `[REDACTED]` marker;
no prefix, exact length or value fingerprint is emitted by this matcher. Counts describe observed worker input; parent
staging omissions set channel `partial` and `staging_incomplete` without inventing
a missing-file count. Unsupported text is summarized in one counted warning
rather than one warning per binary member. Matching recognizes existing credential formats;
it does not estimate arbitrary secret entropy or contact credential services.
Google API key candidates require restriction and usage review and do not prove
a working secret. Certificates alone are not private keys. The absence of a
candidate establishes no protection against reverse engineering or backend
authorization failures. See [AI-assisted attack defense](AI_ASSISTED_ATTACK_DEFENSE.md).

## Xcode test scheduling

Complete directory components such as `MyAppTests` or `MyAppUITests` join `Tests`
and `UITests` in the lowest staging tier. Named unit-test targets require a
multiword uppercase target prefix; explicit named `UITests` targets are accepted.
Single-word names such as `BusinessTests` and `AppTests` remain ambiguous and keep
production priority without a build graph. Matches end at the directory boundary;
names such as `MyAppTestsSupport`, `LatestResults` and lowercase `protests` also
keep production priority. This is a scheduling heuristic, not build-graph proof. It does not
delete or mutate original test inputs, and budgets determine which files can be
staged.

## Bundled legacy binary screening

The bundled Quaygate APK/IPA reader freezes at most 256 MiB of compressed input
in a private temporary file before checking the ZIP directory. Directory metadata
is limited to 8 MiB and 20,000 entries, and its physical records are counted
before `ZipFile` allocates entry objects. ZIP64, concatenated prefixes and
unsupported directory layouts are rejected. Local alignment padding and APK
signing blocks before the directory remain supported. A mutable original path
cannot replace the preflighted snapshot during ZIP parsing. This adds bounded
temporary-file I/O; an over-limit file is unsupported, not a clean result.

Bare `AES` is a default-cipher candidate only when a bounded entry-prefix proof
binds that literal to the first argument of `Cipher.getInstance`. It is not
inferred from a key label elsewhere in the method. Control-flow ambiguity and
exception handlers limit that proof. Other legacy algorithm indicators retain
their documented method/string heuristics; none proves whole-program dataflow,
reachability or a vulnerability. The unified parser's OS isolation and the direct
legacy CLI's in-process limits remain distinct as described in the threat model.

### Kotlin stored initialization and explicit extension calls

For eligible named top-level Kotlin classes and objects, stored property right-hand sides and init blocks are examined in declaration order in a fresh primary-constructor context. Constructor parameters are available during that pass; only stored val/var parameters and stored properties are carried into ordinary method analysis. The construction values and reachable storage remain separate from later method summaries, so a later write is not mistaken for an earlier initializer value. This is bounded source analysis within a nominal body, not proof of cross-class JVM initialization order, component reachability, or a general constructor-argument mapping. Existing execution and field-summary limits still apply.

Custom property reads retain their existing unavailable-accessor boundary: the backing initializer is examined, but its raw value is not asserted to be the getter result. Delegates, nonconstant primary-parameter defaults and unsupported stored-initializer contexts receive an affected precision reason when their execution is unavailable; resource cuts remain budget reasons. Existing inline local/anonymous initializer and accessor-body analysis stays separate. A direct modeled sink in a supported property RHS is examined even when that property has an accessor.

Default inspection is independent of whether a primary parameter is stored. A nonstored parameter's nonconstant default containing a modeled source or sink receives Kotlin constructor default argument flow unavailable at the default expression. The analyzer does not execute that conditional default or publish the parameter as a field. Stored parameters keep their existing initialization reason; this does not establish general constructor-call argument mapping.

Explicit calls to visible compatible project String extensions with source-derived receiver data now record Kotlin project extension receiver flow unavailable at the affected call when no ordinary target or modeled member determines execution. Such coverage is limited rather than silently checked; this does not assert that the extension body or its sink executed. Constant receiver controls and unrelated ordinary project calls keep their existing behavior. Receiver evidence is read without evaluating a source body, and pure type/attribution queries do not acquire this execution diagnostic. Dual dispatch/extension-receiver execution and general Kotlin overload resolution remain outside this bounded model.

This receiver proof includes safe-call nonnull branches, explicit !! assertions and explicit String declarations for the current nominal's stored properties and val/var constructor parameters. The nonnull fact is retained before expression unwrapping. It preserves lexical binding, alias/nullability, getter/delegate and nearer-receiver boundaries; a value's source traces alone do not establish String identity. It does not add general inference for another object's fields or execute accessors to obtain a receiver fact.

Within the existing Kotlin content-lambda model, an indexed write to an otherwise unbound implicit-receiver property contributes its written data to the produced content. Local or explicitly bound maps and a rebound receiver retain their separate effects. Exact Kotlin null literals carry no source data: HTML payload provenance is checked on the payload rather than inferred from null base/history arguments. This bookkeeping is not proof of third-party escaping, complete receiver resolution or an exploitable WebView injection.
