# Project Master Policy (Rust/WASM/Edge Application)

## Introduction and Scope

This document defines the **Master Project Policy** for a Rust/WebAssembly Edge application with NATS/JetStream-based asynchronous communication. It consolidates all rules and guidelines from the project's SPEC and policy documents (Prevention, Contracts, Testing, Security, Agents, Architecture, Operations) into a single authoritative reference. All team members and AI development agents must adhere to these rules exactly. The goal is to enable a solo developer (or AI assistant) to maintain enterprise-grade standards in development, testing, security, and operations. **No requirements or rules in this document may be abstracted or omitted** – everything is explicitly defined as Policy-as-Code. If any scenario or rule is undefined here, that situation **must be treated as a failure** (requiring policy update or clarification before proceeding).

**Alignment with SPEC:** The functional requirements and behavior of the application are defined in `SPEC.md`, which is the single source of truth for what the system must do. All development efforts, tests, and reviews **must ensure full compliance with SPEC.md**. This policy document focuses on _how_ to build and maintain the system (processes, quality gates, and constraints) rather than _what_ to build; however, wherever relevant, it references the SPEC to ensure that all processes serve the delivery of the specified features.

**Edge Environment:** The application is intended to run in a distributed Edge setting, leveraging Rust for performance and WebAssembly (WASM) for sandboxing/portability. NATS with JetStream is used for event-driven communication and persistence across services/nodes. The architecture and rules herein are tailored to this context – e.g., designing around asynchronous message passing, ensuring WASM compatibility, and deploying to multiple edge nodes.

**Document Structure:** The following sections cover all critical aspects:

- [Prevention](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#prevention): Pre-merge checks and automation to prevent issues from reaching main.
    
- [Contracts](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#contracts): Interface and data contract management to avoid breaking changes.
    
- [Testing](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#testing): Testing strategy and quality gates.
    
- [Security](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#security): Security practices and verification steps.
    
- [Agents](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#agents): Responsibilities of AI-driven CLI agents in development (audit, generation, etc.).
    
- [Architecture](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#architecture): System design, layering (Ports & Adapters), and file organization.
    
- [Operations](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#operations): CI/CD pipeline, deployment to edge, monitoring, recovery, and scalability.
    

Each section contains concrete rules, required procedures, and tool commands (with expected outputs on failures) where applicable. Cross-references are provided for clarity. **All rules are mandatory**; violations or omissions will result in build/test failures or rejection of changes until fixed.

## Prevention (Merge Guards & Quality Gates)

This section defines automated **prevention mechanisms** to guard the main branch from breaking changes, bugs, or quality regressions. We use strict branch policies and continuous integration (CI) checks that must pass before any code is merged. This ensures that `main` is always in a deployable, stable state.

### Branching and Merge Strategy

- **Trunk-Based Development:** All work is done in short-lived feature branches derived from `main`. Changes are integrated to `main` frequently via pull requests (PRs). The `main` branch must remain deployable at all times.
    
- **Pull Requests & Reviews:** Every change must be submitted via PR, even if one developer is working alone. The PR description should reference relevant SPEC.md requirements or issue IDs and summarize changes. No direct commits to main are allowed.
    
- **Code Review Requirement:** At least one review must approve the PR before merge. In a solo-dev scenario, use the automated **Audit Agent** (see [Agents](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#agents)) as a pseudo-reviewer. The Audit Agent (or developer in a different role) must review the code for compliance with this policy and add an approval comment. No PR should be merged without this approval.
    
- **Rebase & Update:** Before merging, the feature branch should be updated with the latest `main` (via rebase or merge) to catch integration issues. The CI must run on the updated code. Branch protection rules will **require** the branch to be up-to-date with `main` and all checks passing.
    

### Required Status Checks (Merge Gates)

The CI pipeline provides several **required checks** that act as gates. All must pass for a PR to be mergeable. The required checks are:

- **Build & Compile Check:** The project must compile successfully for all target platforms:
    
    - **Native build:** `cargo build --all` must succeed on the default host target. This ensures no compile errors or unresolved dependencies.
        
    - **WASM build:** `cargo build --target wasm32-wasi --release` must succeed for WebAssembly target. This ensures the code is compatible with the WASI environment used on edge. Any compilation error (for example, using an unsupported crate in WASM) will fail the build.
        
    - _Failure output:_ If compilation fails, the CI outputs the compiler errors. For example, a typical error message:
        
        ```text
        error[E0433]: failed to resolve: use of undeclared type or module `some_crate`
          --> src/lib.rs:42:5
           |
        42 |     some_crate::some_function();
           |     ^^^^^^^^^ use of undeclared type or module
        ```
        
        The CI will mark the build step as **FAILED** and prevent merging.
        
- **Automated Test Suite:** All tests must pass (see [Testing](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#testing) for test categories). CI runs `cargo test --all` (including unit, integration, and contract tests) and expects a zero exit code.
    
    - _Failure output:_ If any test fails, the CI marks **Tests: FAILED**. The console will show which test failed and why. For example:
        
        ```text
        ---- tests::edge_case_behavior stdout ----
        thread 'tests::edge_case_behavior' panicked at 'assertion failed: `(left == right)` 
          left: `42`, 
          right: `43`', src/domain/calculation.rs:88:9
        note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
        failures:
            tests::edge_case_behavior
        test result: FAILED. 99 passed; 1 failed; 0 ignored; 0 filtered out
        ```
        
        The CI job will stop and report a failure status if any test fails.
        
- **Formatting (rustfmt) Check:** Code must be properly formatted according to Rust style guidelines.
    
    - The CI runs `cargo fmt -- --check`. If any Rust source file is not formatted with `rustfmt` stable style, this step fails.
        
    - _Failure output:_ The formatter prints a diff or lists files that need reformatting. For example:
        
        ```text
        Diff in src/lib.rs at line 10:
        -fn example_function(){ let x=3;
        +fn example_function() {
        +    let x = 3;
        ```
        
        The CI will output an **ERROR** that formatting is incorrect and instruct the developer to run `cargo fmt`. This check prevents petty style issues from being part of code review – formatting must be fixed _before_ merge.
        
- **Lint (Clippy) Check:** Code must pass all configured lints to ensure idiomatic and error-free Rust.
    
    - The CI runs `cargo clippy -- -D warnings`. This treats all Clippy warnings as errors. The lint configuration (in `Clippy.toml` or top of files) may allow certain lints, but by default, any lint warning (especially correctness or pedantic lints) will fail the build.
        
    - _Failure output:_ If Clippy finds issues, it will list them with line numbers and suggestions. For example:
        
        ```text
        error: this let-binding has unit value. #[deny(clippy::let_unit_value)] on by default
          --> src/processor.rs:47:9
           |
        47 |     let _ = println!("Started");
           |         ^ help: consider dropping it
        ```
        
        The CI will mark **Lint: FAILED** and require fixes. Developers must address all Clippy-detected issues or explicitly #[allow] them with justification.
        
- **Dependency Audit (Vulnerability Scan):** The project’s dependencies must contain **no known critical vulnerabilities**.
    
    - The CI runs `cargo audit` (with an updated advisory DB) to scan `Cargo.lock` for any dependency with known security advisories (from RustSec Advisory Database). This step fails if any vulnerability is found that is not explicitly ignored with justification.
        
    - _Failure output:_ `cargo audit` prints a report for each vulnerable crate. For example:
        
        ```text
        Vulnerabilities found:
        Crate: hyper
        Version: 0.14.5
        Title: Integer overflow in header parsing
        Date: 2024-05-10
        ID: RUSTSEC-2024-0001 (CVE-2024-12345)
        Solution: Upgrade to >=0.14.10
        ```
        
        The CI will report **Security Audit: FAILED** along with these details. The merge is blocked until the dependency is updated or properly patched.
        
- **Additional Quality Checks:** Other automated checks are enforced as needed:
    
    - **No Debug/ToDo Flags:** There must be no accidental `dbg!` macros, `unimplemented!()`, `todo!()`, or `println!` calls left in the code, and no `TODO`/`FIXME` comments in committed code. A custom script or linter searches the code for these patterns. If found, the build fails with a message indicating their location.
        
    - **No Large Binary Blobs:** The repository must not include large binary files or secrets. A pre-commit hook or CI step scans for forbidden file types (e.g. `.env` files, secrets like AWS keys using regex). If any are found or if repository size exceeds a threshold, the check fails, outputting the file names that violate the policy.
        
    - **License Compliance (if configured):** If the project restricts third-party license usage (e.g., only MIT or Apache-2.0 allowed), we use `cargo deny` with a `deny.toml` configuration. This will check `Cargo.lock` for licenses and fail if any disallowed license is present. It also warns on multiple versions of the same crate to encourage dependency deduplication.
        
        - _Failure output:_ `cargo deny` prints a report like:
            
            ```text
            License LGPL-3.0 from crate `some_crate v1.2.0` is not allowed by policy
            ```
            
            or
            
            ```text
            multiple versions of crate `serde` found: 1.0.130, 1.0.137
            ```
            
            Such findings cause a **Deny Check: FAILED** status.
            

**Branch Protection:** The repository’s settings must enforce that all the above checks are green before allowing merge. This typically involves marking each CI job as a required status check in Git (or the VCS in use). Merging is blocked until:

- All required checks pass.
    
- The PR has at least one approval (from the Audit Agent or a human).
    
- The branch is up-to-date with latest main (CI should re-run if there were new commits on main).
    

**Automatic Merge Guard:** Optionally, we configure an automation (could be a bot or the Reporting Agent – see [Agents](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#agents)) that automatically merges the PR when all checks and approvals are in place. This helps ensure no lapse in policy (the developer cannot accidentally override or bypass checks).

### Pre-Push/Pre-Merge Hooks (Local Prevention)

Developers should get rapid feedback _before_ pushing code by using local hooks and tools:

- **Pre-commit Hooks:** Set up a Git pre-commit or pre-push hook to run `cargo fmt` (to auto-format code) and `cargo test --quiet` (to run fast checks) locally. This prevents trivial issues from reaching CI. Developers must install these hooks as described in `CONTRIBUTING.md` (which contains the hook scripts).
    
- **Watch Mode:** During active development, use tools like `cargo-watch` to continuously run checks (e.g. `cargo watch -x check -x test -x clippy`). This way, compilation errors or test failures are caught immediately in the IDE or terminal.
    
- **Issue Tracking Links:** Each commit or PR should reference a requirement or user story from SPEC.md (if they are numbered or labeled) to ensure traceability. A commit message should include an ID or section from the spec that it addresses. This helps the Audit Agent verify that changes align with SPEC requirements and none are developed without specification.
    

By enforcing all the above, **any deviation from expected quality or unspecified behavior results in an immediate failure (hard stop)**. Developers (or AI agents) must then fix the issues and push updates before trying to merge again. These prevention measures guarantee that what goes into `main` is already vetted for correctness, style, security, and compatibility.

## Contracts (Compatibility and API/Schema Management)

The **Contracts** section defines how we manage and preserve the public interfaces and data schemas of the system over time. This ensures that changes do not break compatibility or violate the expectations of other components, services, or clients. In an Edge architecture with NATS/JetStream, contracts primarily include message formats and any service APIs or function signatures exposed to other modules. All such contracts must remain backward-compatible; if not, explicit versioning and migration steps are required. Breaking this policy is considered a **critical failure**.

### Defining Contracts and Interfaces

We identify the following as **contractual interfaces** in the project:

- **NATS Message Subjects and Payload Schema:** Each message type published or consumed on NATS (especially those persisted in JetStream) has a defined subject name and data schema. The schema might be a JSON structure, Protocol Buffer message, or Rust struct (serialized via CBOR, JSON, etc.). These definitions are part of the contract between producers and consumers.
    
- **WASM Module Public Functions:** If our WebAssembly component exposes functions or is triggered via a defined interface (e.g., a function called by the host or other services with specific parameters), those function signatures and expected behaviors form a contract. For instance, a WASM function might expect input via `stdin` and produce output via `stdout` in a specific format (as per a command pattern for WASI – this is a contract with the host runtime).
    
- **Public API or CLI (if any):** If the application provides an HTTP API, gRPC service, or CLI commands that others use, those are contracts. (In our case, the focus is messaging, so likely minimal external API beyond NATS subjects.)
    
- **Persistent Data Formats:** Any data stored that might be read by future versions, e.g., data saved in JetStream streams (which might be replayed or processed later by updated code), or snapshot files, must maintain compatibility.
    

All contracts should be explicitly documented (in SPEC.md or an API document). For example, each NATS subject could have a corresponding schema definition (in JSON Schema or proto IDL or Rust struct definition with documented fields). This documentation must be kept up-to-date with the code.

### Backward Compatibility Requirements

**No breaking changes** are allowed to any published interface or data schema without following the versioning policy (see below). This means:

- **Message Schema Changes:** When modifying the structure of messages (e.g. adding or removing fields in a JSON payload):
    
    - **Non-breaking changes:** Allowed changes include adding new optional fields or new message subjects (for new functionality) while retaining old ones. Consumers should ignore unknown new fields (and our code should be written to tolerate additional fields if using a format like JSON).
        
    - **Breaking changes:** Removing a field, renaming a field, changing its data type or meaning, or altering message subject names that others rely on are breaking. These are forbidden on existing message channels. Instead, one must introduce a new message version (perhaps a new subject or a version field) while still supporting the old one for a deprecation period.
        
- **Function Signatures:** If the edge WASM module’s function signature (inputs/outputs) or behavior is expected by a host orchestrator or other service, it cannot change incompatibly. For instance, if a function currently takes input in a specific format via WASI and returns a result, you cannot swap the order of fields or change data semantics without updating the contract version.
    
- **APIs:** Similarly, an HTTP/REST API route or CLI command output cannot change response formats or required parameters in a way that breaks clients. If absolutely needed, provide a new route or a flag for a new format.
    
- **Storage/Data:** If we persist data (say, using JetStream as long-term storage for events), new code must be able to read old data. If we change data format, we must write migration logic or support both formats.
    

The project follows **Semantic Versioning (SemVer)** for any versioned artifacts (crates, APIs, or protocols):

- Backward-compatible additions or changes -> **minor version bump** (for APIs/protocols; e.g. adding new message fields that are optional).
    
- Backward-incompatible changes -> **major version bump** (and ideally avoid these by design).
    
- Patch version for backward-compatible bug fixes or documentation updates.
    

Even if the project is primarily an application (not a library crate), we use internal versioning and communicate changes. For example, if a breaking change to messaging is introduced, we might label the release as version 2.0.0 of the system, and ensure older components won’t accidentally connect to it without adjustment.

### Versioning and Deprecation Procedure

If a breaking change _must_ be made to a contract (as a last resort):

1. **Document and Announce:** Update SPEC.md and CHANGELOG to describe the breaking change and rationale. Announce that we are creating a new version of the interface.
    
2. **New Version Introduction:** Implement the new interface alongside the old. E.g., define a new subject name (like `serviceX.v2.request`) or a new field in messages indicating version, or a new WASM entrypoint function with a different name. The new version should coexist with the old one initially.
    
3. **Backward Compatibility Layer:** If possible, write adapter code so that the system can handle both old and new formats during a transition period. For instance, if the schema changed, code can detect an old message (by version tag or by schema recognition) and translate it internally to the new format, or handle it appropriately.
    
4. **Deprecation Period:** Run both versions in parallel for an appropriate period (could be one release cycle or a specific time). This allows any external clients or distributed components to update to the new version.
    
5. **Removal of Old Version:** Only after confirming that no active component depends on the old contract (or after a clearly communicated date), remove support for the old version. This removal constitutes a major version bump in our system. Before removal, ensure thorough tests (including contract tests) to confirm that the new system can operate without the old interface.
    
6. **Snapshot Backup:** Before removing old behavior, take a snapshot (if applicable) of system state or message streams that might be affected, to ensure no data is lost. (For example, if retiring a JetStream stream or subject, export its data if needed for archival.)
    

**Contract Violations:** If a change is introduced that accidentally breaks a contract (e.g., a field removal without following the above steps), this is treated with highest priority:

- The **Testing** section below describes contract tests that should catch such breaks before merge. A failing contract test indicates a violation.
    
- If a breaking change somehow reaches main or production, it triggers an **incident**. The issue must be fixed immediately either by a hotfix reintroducing compatibility or by fast-tracking the above deprecation procedure (if the break is intentional but mistakenly released).
    
- The root cause (process failure) should be analyzed and this policy updated if needed to prevent future slips.
    

### Schema Management and Tooling

To enforce schema consistency:

- **Schema Definitions:** Maintain machine-readable schema specs for message payloads. For JSON, use `.json` schema files or Rust struct definitions in a dedicated module (with serde for example). For Proto, `.proto` files. These serve as an authority for what fields exist. Changes to these files must undergo strict review.
    
- **Schema Evolution Rules:** Only additive changes are allowed (e.g., adding a new field with a default or making an optional field) without bumping major version.
    
- **IDLs and Codegen:** If using an IDL (like Protocol Buffers, Cap’n Proto, or FlatBuffers) for messaging, use their recommended versioning practices (like reserving field numbers, not reusing old field IDs, etc.). Ensure regeneration of code is part of the build when IDL changes.
    
- **Snapshot Tests for Schemas:** Include tests that serialize a sample of each message type and compare it to a previously saved **golden file** (snapshot). Use Rust snapshot testing (e.g., the `insta` crate or a custom approach) to detect unexpected changes in serialized form. For example, if a struct’s derived `Debug` or JSON output changes, a snapshot test will fail, indicating a possible contract change.
    
    - These snapshot files (stored under `tests/snapshots/` or similar) act as contract samples. If a legitimate change is made (e.g., adding a field that shows up in JSON), the snapshot must be updated _intentionally_. The test failing without intent signals that something changed that needs review.
        
- **Consumer Contract Tests:** If there are known consumers of our messages (even if internal), we maintain contract tests for their expectations. For example, if a UI expects a certain field in the message, a test in our suite might simulate the UI parsing our output and asserting the field exists. This way, if we remove or rename that field, the test fails.
    

### Compatibility Tests and Gates

In the CI pipeline (see [Testing](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#testing)), we include **contract compatibility tests**:

- Special integration tests load a previous version of the API or schema (if available, e.g., via stored examples or via backward-compatibility mode) and ensure the current code can interact with it. For instance, we might store a few messages produced by the old version in a file and test that the new code can parse/process them identically to old code. We may also run the old code's test suite against the new code in compatibility mode if feasible.
    
- If the project is a library crate published to Cargo, we use a semver-checking tool (like `cargo semver` or `cargo breaking`) to compare the new public API with the last released version. The CI can fail if a public function or trait removal, signature change, or other breaking API change is detected without a version bump. (For an application, this is less applicable unless exposing a library or plugin interface.)
    

**Gate on Breaking Changes:** Any detected breaking change (through the tests or tools above) will cause the CI to mark **Contract Check: FAILED**. The output will clearly indicate what broke. For example:

- A snapshot test failure might output diff of expected vs actual JSON.
    
- A semver check might output something like:
    
    ```text
    ERROR: Public API change detected:
      - `fn old_function(x: i32)` removed or changed 
    This is a breaking change.
    ```
    
- A custom contract test might panic with a message: _"Contract violation: field `user_id` missing in new response"_.
    

Such a failure blocks merging until resolved either by restoring compatibility or by formally updating version and related documentation (with approval from maintainers).

**Summary:** All changes must be evaluated for contract impact. When in doubt, assume a change is breaking and follow the safe path (additive change or new version). By enforcing these contract rules, we ensure that asynchronous components and clients remain integrated even as the system evolves, and we avoid hidden breakages that could disrupt production at the edge.

## Testing (Verification Strategy and Quality Criteria)

The **Testing** section defines a comprehensive testing strategy to ensure that the system meets all specifications (from SPEC.md) and that changes do not introduce regressions or bugs. All tests must be automated and run in CI. Test coverage, both in breadth (features covered) and depth (edge cases, load), is crucial. The CI will refuse merges if tests fail or if coverage is insufficient.

### Testing Strategy Overview

We employ multiple levels of testing:

1. **Unit Tests** – Focused on small, isolated pieces of logic (e.g., a single function or method). They run in-memory and do not require external services. Unit tests should cover all critical path logic and corner cases for pure functions (especially in the domain/core layer).
    
2. **Integration Tests** – Testing the interaction of multiple parts of the system or with external components in a controlled environment. This includes tests that involve NATS messaging, database or file I/O (if any), etc. Integration tests ensure that modules work together as expected (e.g., when a certain message is published, the system processes it correctly end-to-end).
    
3. **End-to-End (E2E) Tests** – High-level scenario tests that treat the system as a black box (or nearly so), possibly involving the actual application binary or WASM module running in a test harness. For example, starting a local NATS server and our application (or WASM in a runtime), sending test messages through NATS, and observing outputs or side effects. These validate real use cases from an external perspective and confirm the system meets SPEC.md acceptance criteria.
    
4. **Contract Tests** – (Also mentioned in [Contracts](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#contracts)) Tests that specifically verify that the system’s outputs, APIs, and message formats adhere to the agreed contract. For instance, if we promised another service that a field “X” will always be present in messages on subject Y, a test asserts that condition on sample outputs.
    
5. **Property-Based Tests (if applicable)** – For critical algorithms, we utilize property-based testing (using e.g. the `proptest` crate) to generate many random inputs and verify certain properties hold (e.g., idempotence of an operation, sorting results always sorted, etc.). This can uncover edge cases not thought of in example-based tests.
    
6. **Performance/Load Tests** – We include tests or scripts (possibly not run on every PR, but regularly) to simulate high load or long runtime, ensuring the system performs within expected limits and without memory leaks or deadlocks.
    

All tests are written in Rust (for Rust code) using the standard `#[test]` framework or appropriate harnesses (`#[tokio::test]` for async tests, etc.), and reside in the repository:

- Unit tests are typically alongside code in `src` modules (using Rust’s inline test modules).
    
- Integration tests are in the `tests/` directory as separate files, or in dedicated test crates, to exercise public interfaces.
    
- Additional test data (fixtures, snapshots, test configs) reside under a `tests/` or `fixtures/` directory.
    

### Unit and Integration Tests

**Unit Tests:**

- Every function, module, or component with logic should have unit tests covering:
    
    - **Normal cases** (expected input -> expected output).
        
    - **Edge cases** (boundary values, empty inputs, maximum values, error conditions).
        
    - **Error handling**: tests that ensure the function returns or propagates errors correctly (for example, if a function should return an `Err` on invalid input, we test that path).
        
- Unit tests should avoid external dependencies. Use stubs or mocks for external calls:
    
    - For instance, if a domain function uses a trait for a message bus (port), in unit tests provide a dummy implementation of that trait to simulate behavior.
        
    - No actual NATS network calls in unit tests; instead simulate them (or use an in-memory channel to mimic message passing).
        
- Aim for fast execution (each test typically <10ms) to keep suite quick.
    

**Integration Tests:**

- Use `tests/*.rs` files to write scenarios that involve multiple components:
    
    - Example: Start an in-memory or local NATS server (like using `nats-server` binary in a CI environment or use a NATS library in "demo" mode if available), then run functions that subscribe/publish to it and verify results. The test can connect to `localhost:4222` NATS and simulate a message flow.
        
    - If the system has multiple asynchronous tasks, integration tests ensure they coordinate properly (for example, send a message and wait for the expected output or state change).
        
- Include the database or persistence if applicable. If using JetStream, the test should set up a JetStream context (which in NATS can be done by enabling JetStream on the test server) and then test, for instance, that publishing an event results in it being stored in a stream and later consumed.
    
- Clean up after tests: ensure that any spawned servers or threads are stopped, any temporary files or streams are purged. This can be done in test teardown or by using temp directories.
    

**Asynchronous Testing:** Many components will be async (e.g., message handlers). We use `#[tokio::test]` (or `async_std::test`) to write async tests. These tests run within a runtime and can `await` futures. Ensure the test runtime is compatible (Tokio tests typically require the multi-threaded runtime if testing things in parallel).

**Example Integration Test Scenario:** _"When a `UserCreated` event is published to `events.user.create`, the system should store the user in the database and publish a `UserAcknowledged` event in reply."_  
An integration test for this would:

- Arrange: Start NATS (JetStream enabled), configure a stream for `events.user.*` subjects. Possibly start our application component (if it’s a separate process, spawn it; if it’s a library, call a start function in a thread).
    
- Act: Publish a test message to `events.user.create` with sample user data.
    
- Assert: Check that the database (maybe a temporary SQLite or an in-memory representation) now has that user record, and/or check that a message on `events.user.ack` was published (subscribe to it in the test and await a message).
    
- The test should use timeouts to avoid hanging indefinitely (e.g., if expecting a message, wait up to X seconds).
    

### End-to-End Testing

For end-to-end tests, we simulate the **real deployment scenario** as closely as possible:

- **WASM Execution E2E:** Compile the Rust code to a `.wasm` module (as in production). Use a WASM runtime (like Wasmtime or Wasmer via Rust or CLI) to run the module. Feed it inputs and observe outputs:
    
    - For example, if our WASM module is triggered by NATS as per the Nex model (subject + payload via stdin), we can mimic that. Run the WASM with `wasmtime`, provide arguments and stdin as test input, and capture stdout.
        
    - Verify the stdout (response) is correct given the input. Also verify side effects: if the WASM is supposed to publish something, in the test environment perhaps the WASM itself might call a host function (if we provide one via WASI). If not possible, we rely on integration tests for messaging behavior.
        
- **Full System Run:** In some cases, we might run the entire system as a process for testing:
    
    - Example: Launch a local NATS server and a binary of our app (if we have a standalone mode) in a subprocess, then perform a series of interactions (like an external client would). This could be orchestrated via a shell script or a test harness that spawns processes and communicates (perhaps using CLI or network calls).
        
    - Check end results (like final state or outputs).
        
- **Spec Compliance Tests:** Write tests directly from SPEC.md requirements. For each user story or requirement "The system shall do X", ensure there's at least one test verifying X. This acts as acceptance tests. For traceability, include the SPEC reference in the test description or name (e.g., `#[test] fn spec_requirement_4_1_user_create()`).
    

Because E2E tests can be slower or more complex (involving actual I/O and processes), we might not run all of them on every PR by default. The most critical ones, however, should be part of CI to prevent breaking core use cases. Less critical or very heavy tests can be run nightly or on merges to main.

### Test Coverage and Quality Criteria

We uphold a high standard for test coverage:

- **Coverage Threshold:** The project must maintain at least **90% code coverage** for domain and application logic. Critical modules (those implementing core business logic per SPEC.md) should approach 100% coverage. We measure coverage via `cargo tarpaulin` or similar.
    
    - The CI can run `cargo tarpaulin --out Xml` to produce a coverage report. A coverage gating script then parses it and fails if below threshold. It will output something like:  
        `Code coverage is 88.5%, which is below the required 90%. Tests coverage gate FAILED.`  
        This prevents merging until more tests are added.
        
- **Testing New Code:** Any new code (new features, bug fixes) must be accompanied by appropriate tests. The PR should not introduce untested significant logic. This is enforced by review (Audit Agent will check diff for lack of tests) and by coverage changes (if coverage drops or does not increase for new functionality, that’s a red flag).
    
- **No Flaky Tests:** All tests must be deterministic. Flaky tests (those that intermittently fail/pass) are not allowed. If a test is found to be flaky (e.g., due to timing or ordering issues), fix the underlying cause or adjust the test to be reliable (e.g., use longer timeouts or deterministic seeding for randomization). CI is set to possibly re-run tests on multiple seeds if using property tests, to ensure reliability.
    
- **Isolation:** Tests should not interfere with each other. Each test should use isolated resources:
    
    - Use unique temp directories or file names (Rust’s `tempfile` or similar).
        
    - If using a global service like NATS in multiple tests, start/stop per test or use distinct subjects to avoid crosstalk.
        
    - Ensure global state (if any) is reset between tests (prefer avoiding global mutable state entirely).
        
- **Performance of Tests:** Try to keep the entire test suite execution time reasonable (e.g., under a few minutes). Use parallel test execution (Cargo runs tests in parallel by default on multiple threads) – ensure tests are written to be parallel-safe (they use different resources).
    
- **Continuous Testing:** Developers should run tests locally often. The CI will run them on each push. We also have a nightly scheduled run of the full test suite (including any slow exhaustive tests) to catch issues that might not appear in a quick PR run.
    

### Test Execution in CI (and Failure Outputs)

The CI pipeline’s **Test stage**:

- Runs `cargo test --all --all-features` from the project root. (All features flag ensures we test any optional compilation features as well).
    
- Environment: The CI configures necessary services (e.g., starts a NATS server in the background on `localhost` for integration tests, possibly via a Docker container or a GitHub Actions service). The environment variables or config files are set so that tests know how to connect (e.g., `NATS_URL=nats://127.0.0.1:4222`).
    
- If any test fails, as described, Cargo will exit with code != 0. The CI then marks the test job failed. The failure log (as shown in examples above) will be available for debugging.
    
- If tests pass, CI proceeds to next steps (e.g., security audit). On success, we might see an output summary like:  
    `test result: ok. 150 passed; 0 failed` and a coverage summary if measured.
    
- We configure CI to use the verbose mode for tests (`cargo test -- --nocapture` in some cases) to see logs from tests if a failure occurs, which aids debugging.
    

### Testing Special Scenarios

- **Error Handling Tests:** Deliberately inject errors or use fakes to ensure the system handles them gracefully. For instance, simulate NATS being unavailable (maybe by pointing to a wrong port or shutting it down mid-test) to ensure our code logs an error and retries appropriately as per spec.
    
- **Security Tests:** Although covered in [Security](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#security), note that we also test security-related behavior. E.g., if the spec says "the system should not process messages from unauthorized subjects", write a test that publishes a message to a disallowed subject and assert it’s ignored or raises an alert.
    
- **Concurrency Tests:** If the system processes messages concurrently, write tests that send multiple messages in parallel and ensure internal data structures remain consistent (no race conditions). Use tools like Loom for testing concurrency if necessary (Loom can systematically explore thread interleavings in Rust).
    
- **Fuzz Testing:** For parts of the code that parse external input (like if a message payload includes user-provided data), employ fuzz testing. We can have a fuzz target using `cargo-fuzz` (not run in every CI but regularly) to generate random inputs and ensure the code doesn’t panic or overflow. If any fuzz case finds a problem, add a regression unit test.
    

In summary, the testing policy is **extremely strict**: every expected behavior from SPEC.md must have tests, and any bug fix gets a new test to prevent recurrence. The Testing gate in CI, combined with high coverage, ensures that we catch issues early. A merge is only allowed when the entire test suite passes and meets quality criteria, with clear output on any failure so it can be quickly resolved.

## Security (Secure Development & Verification)

Security is a first-class concern. This section details how we build security into the software (secure coding practices) and how we verify security (through analysis and checks). The aim is to protect the application and its data in an edge environment where threats include network attacks, unauthorized access, and vulnerabilities in dependencies. A failure to comply with security requirements (e.g., merging code with known vulnerabilities or introducing a security bug) is not permitted.

### Secure Coding Standards

All development must follow secure coding best practices:

- **Memory Safety:** Use Rust’s safety guarantees to our advantage. Avoid using `unsafe` code. If `unsafe` is absolutely necessary (e.g., for FFI or performance optimizations), it must be reviewed carefully:
    
    - Clearly comment any `unsafe` block with justification and ensure it cannot cause memory corruption or undefined behavior. The Audit Agent should specifically scrutinize unsafe usages.
        
    - Prefer well-vetted unsafe abstractions from crates (e.g., using `crossbeam` or `arc-swap` instead of rolling your own concurrency primitives).
        
- **Input Validation:** All external inputs (message payloads from NATS, environment variables, config files, any API requests) must be validated for type, format, and bounds:
    
    - Use strong types for message fields (e.g., if an ID should be numeric, define it as an integer type).
        
    - Check for missing or malformed fields in messages and handle gracefully (e.g., ignore or send an error response rather than panicking).
        
    - Validate lengths of strings, ranges of numbers, etc., according to SPEC. Reject or sanitize any data that doesn’t meet expectations.
        
- **Error Handling:** Handle errors explicitly and securely:
    
    - Use `Result` and `?` to propagate errors up, or handle them where appropriate. Do not ignore errors (no `.unwrap()` or `.expect()` in production code, unless it's absolutely certain and documented).
        
    - When logging errors, do not leak sensitive information (e.g., do not log full payloads if they might contain private data; log an identifier instead).
        
    - Ensure that recoverable errors (like a transient NATS disconnection) trigger retries or failover rather than crashing the application.
        
- **Authentication & Authorization:** If the application requires auth (for example, connecting to NATS with credentials, or if it exposes an API):
    
    - Never hard-code credentials or secrets in code. Use environment variables or configuration files and ensure they are secured (see Secrets Management below).
        
    - Follow the principle of least privilege. For NATS, use user credentials that only permit the subjects needed (e.g., if the app only needs to subscribe to `events.*`, don’t give it full wildcard publish rights on all subjects).
        
    - If multiple roles or services exist, implement authorization checks as per spec (for instance, if an incoming message should only be processed if it came from a trusted source, include a signature or token and verify it).
        
- **Data Protection:** If the application handles sensitive data:
    
    - Use encryption for data at rest and in transit. JetStream data at rest should ideally be on encrypted disks if possible. For data in transit, ensure NATS connections use TLS (NATS can be configured with TLS; our client should verify server certificates).
        
    - If the system writes any logs or metrics to a centralized system, ensure those channels are secure (HTTPS or authenticated ingestion).
        
    - Avoid storing sensitive data in logs. Mask or hash it if needed for debugging.
        
- **WebAssembly Security:** Running code as WASM provides sandboxing, but be mindful:
    
    - If using WASI, only grant the minimal required permissions (e.g., if the WASM module doesn’t need file system access, do not mount any host dirs).
        
    - Keep the WASM runtime updated to pick up security fixes.
        
    - If multiple WASM modules communicate, treat their interfaces as untrusted (validate data passed between modules too, since a compromise in one module shouldn’t trick another).
        

### Dependency and Supply Chain Security

We rely on third-party crates and external software (NATS server, etc.). These must be managed securely:

- **Vulnerability Scanning:** (As mentioned in [Prevention](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#prevention), Required Checks) We run `cargo audit` on every commit and regularly (daily scheduled job) to catch any new vulnerabilities. Any flagged vulnerability must be addressed immediately by upgrading the crate or applying a patch (e.g., using `[patch]` section in Cargo.toml if waiting for upstream fix).
    
- **cargo-deny for Advanced Checks:** We integrate `cargo-deny` in CI to perform:
    
    - Vulnerability check (similar to cargo audit, possibly redundant but ensures updated advisories).
        
    - **License compliance:** Define allowed licenses (e.g., MIT or Apache-2.0, etc.) in deny config. CI will fail if a dependency with a disallowed license is added. This prevents legal/security issues with viral licenses.
        
    - **Unmaintained or Forked Crates:** cargo-deny can warn if a crate is unmaintained or yanked. We treat such warnings seriously: if a crate is no longer maintained and it’s critical, consider finding an alternative or forking and patching it.
        
    - **Multiple Versions:** cargo-deny highlights if the project depends on multiple versions of the same crate (which can increase attack surface or binary size). While not an immediate failure, we aim to deduplicate dependencies where possible.
        
- **Pinned Dependencies:** Use `Cargo.lock` to lock versions for reproducible builds. Do not override dependency versions without reason. For binaries, commit `Cargo.lock`. For libraries, ensure to document required versions.
    
- **Git Dependencies:** Avoid using `git` repositories for dependencies unless absolutely needed (prefer crates.io versions). If used, pin to a specific commit and periodically review for updates or changes (since `cargo audit` might not cover git deps as thoroughly).
    
- **Third-Party Tools:** The NATS server and any other external services should be kept updated. Monitor their security advisories (subscribe to NATS mailing list or RSS for releases). When a new version is released with security fixes, plan to upgrade our deployments promptly after testing compatibility.
    

### Secrets Management

Secure handling of secrets (like API keys, NATS credentials, etc.):

- **Configuration:** All secrets and sensitive configurations (e.g., database passwords, NATS JWTs or NKeys if using NATS auth) must be stored outside of code, typically in environment variables or secure config files. For local development, use a `.env` file (which is .gitignored). In production, use the orchestration platform’s secret store (e.g., Kubernetes secrets or cloud parameter store).
    
- **No Hardcoded Secrets:** The codebase must not contain any secret tokens, keys, or passwords. A secret scanning tool (like trufflehog or GitHub’s secret scanner) should be enabled to detect if any commits introduce something looking like a secret (AWS keys pattern, etc.). If detected, the CI fails and the secret must be invalidated if it was real.
    
- **Minimal Secret Scope:** Only provide each environment or component the secrets it strictly needs. For example, if our app only needs NATS credentials, don’t also give it database credentials for another service.
    
- **Rotation:** For long-lived deployments, have a plan to rotate keys periodically. This might be manual if one-person, but document how to update a NATS credential or any other key the app uses, without downtime (e.g., support reading new credentials on reload, or bring up new instance with new cred before shutting old).
    

### Security Testing and Analysis

In addition to prevention and coding standards, we actively test for security issues:

- **Static Analysis:** Clippy and Rust compiler already catch many issues. We might add more static analysis tools:
    
    - Use `cargo clippy` with additional lints for security (like `cargo geiger` can detect usage of unsafe code metrics).
        
    - Consider using a formal analyzer like Prusti or Klee on critical algorithms if feasible, though this is advanced.
        
- **Fuzz Testing:** As mentioned, fuzz test any component that handles external input, to catch panics or overflow. E.g., fuzz the message parser with random bytes to ensure it doesn’t panic or loop infinitely.
    
- **Penetration Testing:** Although an internal message-driven system is not directly exposed like a web server, if there are any externally facing interfaces, attempt to penetrate them:
    
    - If there's an HTTP endpoint or CLI, test for typical issues (SQL injection, command injection, though our app likely doesn’t use SQL or shell).
        
    - If the app writes to file or interacts with the OS via WASI, ensure path traversal or similar is not possible (use allowed dirs only).
        
    - Try malformed or malicious messages: e.g., extremely large payload, or payload intended to break JSON parser, etc., and ensure the app either safely handles it or rejects it without crashing.
        
- **Dependency Audit during development:** Developers should run `cargo audit` after adding a new dependency to catch if it’s already known vulnerable. Also, check the crate’s reputation and maintenance status (e.g., look at last commit, open issues) before introducing it.
    

### Security Gate in CI

The CI **Security stage** (which may coincide with prevention checks) ensures no known security issues slip in:

- As described, `cargo audit` and `cargo deny` are run. If vulnerabilities are found, the build **fails**. The output clearly identifies the CVE or RUSTSEC ID and crate, so the developer can act (usually by updating the crate version to one that patches the flaw, or applying a temporary patch).
    
- If a vulnerability cannot be immediately resolved (e.g., no fixed version yet), the issue must be documented and a temporary exception added in `cargo-audit` allow list (with a comment explaining the risk and mitigation). These exceptions should be rare and reviewed.
    
- The CI also runs any custom security tests. For example, a test that ensures certain endpoints require auth will run in the test suite.
    
- We treat any security test failure with the same severity as a functional test failure: fix required before merge.
    

_Failure output example:_ If `cargo audit` finds a vulnerability:

```text
error: 1 vulnerability found!
Crate: smallvec
Version: 1.6.0
Title: Buffer overflow in SmallVec::insert_many
Date: 2021-02-18
ID: RUSTSEC-2021-0003
Solution: upgrade to >=1.6.1
```

CI will log this and mark the job failed. The PR cannot be merged until `smallvec` is upgraded to 1.6.1 or later.

### Incident Response and Monitoring for Security

(This overlaps with [Operations](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#operations), but reiterating security aspects.)

- **Logging:** The application should log security-relevant events at an appropriate level. For instance, if an authentication failure occurs or an unexpected message is received from an unknown source, log a warning or error with details. These logs help detect potential intrusion or misuse.
    
- **Monitoring:** Set up alerts (see Operations) for unusual patterns, e.g., a surge in rejected messages (which could indicate a spam or attack attempt), or repeated failures to connect to NATS (could indicate MITM or NATS down).
    
- **Patches:** When a security patch is needed (for our code or a dependency), treat it as hotfix priority. Even if one developer, don't wait for a long batch of changes – address it as a focused update, and deploy as soon as tests pass.
    
- **Review:** The Audit Agent (or code reviewer) should include security in the review checklist: e.g., “Does this code introduce any potential overflow? Are all inputs validated? Does it expose any new open ports or subjects that could be abused?” This is a conscious step in PR review.
    
- **Social Engineering Safe-guards:** (Even in solo dev) be mindful of supply-chain attacks: e.g., verify the source of new dependencies (ensure it's the intended crate, not a typosquat). Use Cargo’s `dependency rename` feature to avoid ambiguous names if needed.
    

By following these security guidelines and automating enforcement where possible, we ensure the project remains secure against common vulnerabilities and threats. **No code is merged if it lowers the security posture** or introduces unresolved risks.

## Agents (AI CLI Agents Responsibilities and Workflow)

To assist the solo developer and maintain consistent enforcement of this policy, we utilize specialized **CLI Agents** (potentially powered by AI, e.g., Claude or similar). Each agent has a defined role and they collaborate in the development lifecycle. These agents act as “virtual team members” handling different concerns: auditing code, generating code, ensuring contracts, verifying tests, and reporting outcomes. This section defines each agent’s responsibilities and how they interoperate. All agents must themselves operate within the rules of this Master Policy (they treat this document as the guiding instructions).

### Audit Agent

**Role:** The Audit Agent serves as an automated code reviewer and compliance officer. When invoked (e.g., via `ai-cli audit`), it will:

- **Review Code Changes:** Analyze the diff or the entire codebase for any violations of the guidelines in this policy. This includes checking for:
    
    - Missing tests for new code (flag if a new function or module lacks corresponding tests).
        
    - Complexity or architecture violations (e.g., if a domain layer tries to directly use an adapter implementation, or any dependency rule in [Architecture](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#architecture) is broken).
        
    - Code style issues not caught by automated tools (e.g., inconsistent naming that might confuse, though this is minor compared to clippy).
        
    - Potential bugs or spec deviations (the agent should verify that the logic of changes still aligns with SPEC.md; e.g., if SPEC says an edge case should be handled and code doesn’t, that's a finding).
        
    - Security issues (unused `unsafe`, use of deprecated functions, printing secrets, etc.).
        
- **Use of Tools:** The Audit Agent can internally use static analysis (like running clippy, which it then interprets) or parse code. It should also reference SPEC.md and ensure the code covers all requirements or at least doesn’t violate them.
    
- **Output (Audit Report):** The agent produces a report listing any issues found. For each issue, it references the policy section and provides detail. For example:
    
    - _"AuditAgent: ERROR - Found direct call to NATS client in domain logic (src/domain/user.rs:45). This violates the Port/Adapter separation (see Architecture section). Propose moving this call to an adapter."_
        
    - _"AuditAgent: WARN - Function X lacks test coverage. Add unit tests (Testing section)."_
        
    - _"AuditAgent: OK - No security vulnerabilities or style issues detected."_
        
- **Approval Decision:** If the Audit Agent finds no policy violations (or only minor warnings that have been addressed or acknowledged), it can approve the PR. It might add a comment or set a status like "Audit Passed". If issues are found, it will advise corrections and **not approve** until they are resolved.
    
- **Continuous Audit:** The Audit Agent can also run on a schedule on the main branch to detect any drift or issues that sneaked in. But primarily, it’s used at PR time.
    

**Note:** The Audit Agent does not modify code (it’s not an auto-fixer; that’s the Generation Agent’s job if needed). It provides an impartial analysis. Think of it as a combination of a senior engineer code reviewer and a static analyzer.

### Generation Agent

**Role:** The Generation Agent is responsible for creating or modifying code based on high-level instructions. For example, when the developer needs to implement a new feature or fix a bug, they can use `ai-cli generate <feature-description>` and the Generation Agent will produce code that meets the spec and the coding standards.

Responsibilities:

- **Feature Implementation:** Given a requirement (preferably directly referenced from SPEC.md), the agent writes the necessary Rust code (and possibly tests) to fulfill it. It should break down the task, consider where in the architecture the changes go (perhaps consult the Architecture section for the correct layer), and generate code accordingly.
    
- **Adherence to Spec:** The agent must strictly follow SPEC.md for functionality. If the spec is ambiguous, it should ask for clarification or refer to examples. It should not introduce functionality that isn't specified or omit required functionality.
    
- **Include Tests:** For any new function or module, the Generation Agent should also generate unit tests (and possibly integration tests if applicable). This way, it directly contributes to maintaining coverage and ensuring the new code is testable.
    
- **Use Proper Style:** All code generated must already be `rustfmt` formatted and Clippy-clean as much as possible. The agent should run an internal formatting on the code snippet and check with lint rules before output, to minimize CI issues.
    
- **No Secrets or Hardcoding:** The agent should not hardcode values that should be config (like URLs, credentials). For instance, if generating code to connect to NATS, it should fetch the URL from a config or env variable, not directly embed `nats://localhost`.
    
- **Placeholders and TODOs:** Ideally, the Generation Agent should avoid leaving `TODO` in code. If some piece is not specified or needs later attention, it should explicitly call it out in comments and maybe notify the developer, rather than leaving a casual TODO that might be forgotten. Alternatively, integrate with the Audit Agent to ensure any placeholder is tracked.
    

**Workflow:** The developer (or an orchestrating script) would typically run:

1. `ai-cli generate "Implement feature X as described in SPEC section 3.2"` – The agent outputs code and possibly file names.
    
2. The code is then inserted into the repository. The Generation Agent might directly create a new branch/commit via CLI.
    
3. Immediately after, tests would run (by Verification Agent) and Audit Agent would review. The Generation Agent might be called again to refine code if tests fail or audit finds issues:
    
    - e.g., if a test fails, one could invoke `ai-cli generate "Fix the failing test by adjusting logic"` or even have the Verification Agent trigger generation of a fix.
        
    - If Audit Agent flagged a design issue, the developer can instruct Generation Agent to refactor accordingly.
        

**Limits:** The Generation Agent should not merge code by itself. It proposes changes which then must pass through audit and verification gates.

### Contract Agent

**Role:** The Contract Agent ensures that system interfaces and data contracts remain consistent and properly versioned as per the [Contracts](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#contracts) rules. It acts as a specialist focusing on compatibility.

Responsibilities:

- **Interface Change Detection:** Whenever code changes involve public interfaces (e.g., a struct that is part of a message payload, a function signature in an interface module, or an API endpoint definition), the Contract Agent is triggered. It checks:
    
    - If the change is backward-compatible (e.g., adding a new optional field to a struct) or potentially breaking (e.g., removing or renaming a field).
        
    - If it’s breaking, ensure the versioning procedure is followed (has the version been bumped? Are both old and new handled?).
        
    - If a schema file (JSON schema or proto) is updated, verify that changes adhere to allowed modifications.
        
- **Automated Contract Tests:** The Contract Agent can run the suite of contract tests specifically, or even generate new tests if a new interface is added. For example, if a new message type `OrderCanceled` is introduced, it might prompt generating a snapshot test for it or ensuring documentation is updated.
    
- **Documentation Update:** Ensures that any contract change is reflected in documentation (SPEC.md or a separate API doc). If it notices a discrepancy (code has a field that spec doesn’t mention, or vice versa), it flags it. It may even draft a spec update for review.
    
- **Snapshot Management:** If snapshot files are used for testing (see Contracts section), the Contract Agent can assist in updating snapshots when intentional changes occur:
    
    - It will confirm that any snapshot test failure corresponds to an expected, intentional change (as part of a planned version bump or feature) and not an accidental break.
        
    - If intentional, it can regenerate the snapshot file (with human oversight or via command) and include it in the commit, along with notes that this is a version change.
        
- **Coordination on Versioning:** If a breaking change is being introduced, the Contract Agent will orchestrate the proper steps:
    
    - Remind the developer to bump crate versions or API version constants.
        
    - Possibly modify CI/CD to handle dual versions during transition.
        
    - Alert the Operations (deployment) about potential incompatibilities (so they know not to deploy partial updates that mix versions incorrectly).
        

**Example:** Developer changes the `UserCreated` message format, removing a field `age`. The Contract Agent would:

- Catch that `age` field removal is a breaking change.
    
- It will fail the current build’s contract check (because tests expecting `age` would fail).
    
- It informs: “Removing field `age` from UserCreated is a breaking change. According to Contracts policy, you must version this change. Options: (a) reintroduce `age` and deprecate later, (b) create a new message subject/version for this and handle both for now. The current action is blocked.”
    
- If developer then chooses to create a new version (say `UserCreatedV2` message on a new subject), the Contract Agent will ensure that all references are updated and that both old and new are handled. It might generate a stub handler for old messages if needed (like one that logs a warning that old version is deprecated).
    
- Only after these steps, and updating documentation, would the Contract Agent “approve” the contract aspect.
    

### Verification Agent

**Role:** The Verification Agent runs and manages tests and quality checks (essentially orchestrating the Testing and some Prevention steps through an AI assistant). It ensures that after generation or any code change, the entire test suite is executed and results are interpreted.

Responsibilities:

- **Run Test Suite:** When invoked (e.g., `ai-cli verify` or as part of a pipeline), it triggers the execution of all tests, perhaps by calling the appropriate CI scripts or directly running `cargo test`, `cargo clippy`, etc., in sequence (mirroring what CI does).
    
- **Aggregate Results:** It collects the results of these runs:
    
    - Did any unit/integration tests fail? Which ones?
        
    - Did any required check (format, lint, audit) fail?
        
    - It then prepares a summary.
        
- **Intelligent Analysis:** Beyond just running tests, the Verification Agent can analyze failures to categorize them:
    
    - If a test failed, it can parse the output to identify the assertion and maybe even pinpoint likely causes or relevant recent changes.
        
    - If Clippy failed, it can suggest the needed fixes (since Clippy gives suggestions, the agent can surface those).
        
    - If formatting failed, it will simply note that rustfmt needs to be run (and could even auto-run it if allowed).
        
- **Automated Fix Trigger:** Optionally, the Verification Agent could trigger the Generation Agent to fix certain classes of issues:
    
    - For example, if tests fail due to an off-by-one error or an unwrapped Result, the Verification Agent can call the Generation Agent with a prompt like "Fix the failing test by adjusting X as suggested by the assertion."
        
    - For lint issues, it could ask Generation Agent to apply the Clippy suggestions to the code.
        
    - This automation should be controlled (perhaps only for trivial fixes) to avoid going in circles; complex logic failures likely need human or at least a careful prompt.
        
- **Performance of Tests:** The Verification Agent monitors the test run for any performance issues (e.g., if tests hang or take too long). If a test seems stuck or consistently timing out, it flags that for investigation, as it might indicate a deadlock or infinite loop introduced.
    
- **Gatekeeping:** The Verification Agent ultimately decides if the code passes all checks. It will give a final verdict:
    
    - "Verification PASSED: All tests and checks succeeded. You may proceed to merge."
        
    - Or "Verification FAILED" followed by details of what failed.
        
- This agent essentially acts like the CI pipeline in conversational form, guiding the developer/AI on what to fix.
    

**Integration with CI:** In practice, the CI itself will run tests, but the Verification Agent can be used during local development or as part of an AI-driven workflow to pre-validate before even pushing. It ensures that by the time code is submitted, it's likely to pass CI (saving time).

### Reporting Agent

**Role:** The Reporting Agent aggregates information from all other agents and the CI process, and communicates it to the developer (and possibly stakeholders). It’s responsible for logging and alerting. In a multi-agent automated scenario, it is the final voice that says "All good, deploying" or "Issues found, needs attention."

Responsibilities:

- **Summary Reports:** After a development session or CI run, the Reporting Agent provides a summary of results:
    
    - For example: _"Summary: Code generation completed. Audit found 2 issues (fixed). All 142 tests passed. Security audit clean. Ready to merge."_
        
    - Or in case of failure: _"Build failed: Clippy found 3 warnings and 1 test failed. See Audit/Verification details above. Not merged."_
        
- **Alerting:** If a critical problem arises (like a security vulnerability discovered, or production incident as covered in Operations), the Reporting Agent can notify in multiple channels:
    
    - Print to console with special highlighting.
        
    - Possibly send an email or chat notification if configured (for a solo dev, maybe a local notification).
        
    - Create a GitHub issue or JIRA ticket automatically if something needs long-term tracking (like "Dependency X vulnerable, awaiting patch", so it’s not forgotten).
        
- **Documentation & Logging:** The Reporting Agent ensures that important decisions and changes are documented:
    
    - It can append notes to a CHANGELOG.md for release notes based on commit messages and agent findings (e.g., "Added feature X, fixed bug Y, no breaking changes.").
        
    - If a contract version was bumped, it logs that this is a major release event.
        
    - It might update an “Agent Log” file or a comments section in PR with a transcript of what happened (for auditability of AI actions).
        
- **Incident Reporting:** In case of a runtime incident (monitored in Operations), the Reporting Agent might take input from monitoring alerts and generate an incident report:
    
    - e.g., "ALERT: Edge node 3 experienced a crash at 2025-08-01 10:00 UTC. Automatic restart succeeded. Crash log attached. Please investigate."
        
    - It could create a postmortem template for the dev to fill out if needed.
        
- **Coordination:** When all checks pass, the Reporting Agent might coordinate next steps:
    
    - It can automatically merge the PR if configured (saying "All checks passed – merging PR #123").
        
    - It can trigger the deployment pipeline (handing off to Operations section tasks).
        
    - If something is waiting for human review (like a policy decision), it pings the responsible person.
        

**Collaboration Workflow:** Here’s how these agents typically work together in a development cycle:

1. **Planning:** Developer defines a task (ref from SPEC). Possibly the Reporting Agent logs this as a new feature branch opened.
    
2. **Generation:** Generation Agent writes code for the task.
    
3. **Audit:** Audit Agent reviews the new code, finds a couple of minor issues.
    
4. **Fixes:** Either developer manually fixes or Generation Agent is called to adjust code as per Audit feedback.
    
5. **Verification:** Verification Agent runs tests and checks. Suppose one test fails.
    
6. **Debug:** Developer or Generation Agent fixes the logic for the failing test.
    
7. **Re-verify:** Tests now pass. Audit re-runs quickly to ensure no new issues.
    
8. **Reporting:** Reporting Agent summarizes: "Feature X implemented and verified successfully."
    
9. **Merge/Deploy:** With all clear, either automatically merge or prompt developer to merge. Then possibly trigger deployment (Operations).
    
10. **Post-merge:** If this is merged to main, Reporting Agent updates release notes.
    

All agent interactions should be logged for transparency. The developer oversees this pipeline, intervening as needed. The net effect is that even as a single person, the developer can rely on these agents to enforce all the rules and catch mistakes, mimicking a robust team process.

**Failure Handling:** If any agent fails to do its job correctly (e.g., Generation Agent outputs code that doesn’t compile, or Audit Agent misses a glaring issue), the policy treats it as a system failure:

- The error should be caught by another stage (like compile or tests).
    
- The developer should then improve the prompt or logic for the agent or handle the fix manually.
    
- We continuously refine the agent prompts (which likely includes this very document) to improve their reliability.
    

Thus, these Agents form a cohesive automated framework ensuring this Master Policy is applied consistently from code inception to deployment.

## Architecture (Layered Design and Dependency Rules)

The **Architecture** section defines how the codebase is structured into layers and modules, following a Port-and-Adapter (Hexagonal) architecture suitable for Rust and the target Edge environment. It also specifies dependency constraints between modules to enforce separation of concerns and facilitate maintainability, testability, and ability to deploy in distributed edge scenarios. Any deviation from this prescribed architecture (e.g., a dependency that violates layer rules or incorrect placement of code) is considered a design failure and must be corrected.

### Layered Architecture Overview

We divide the system into clear layers, each with specific responsibilities:

- **Domain (Core) Layer:** Business logic, state, and rules defined here, independent of any tech specifics. Pure Rust code with no external side-effects (no network, no file I/O, etc.). This is the heart of the application where we implement SPEC-defined behaviors.
    
- **Ports (Interface) Layer:** Abstract interfaces (traits in Rust) that define the boundary between the domain and external services or infrastructure. Ports represent capabilities the domain needs (e.g., a messaging service, a storage service) without binding to a concrete implementation. They also include interfaces for driving the application (e.g., inbound port for receiving events).
    
- **Adapters (Infrastructure) Layer:** Concrete implementations of the Port interfaces, handling real I/O and integration with external systems. Examples: a NATS JetStream adapter implementing a `MessageBroker` trait, a database adapter implementing a `Repository` trait, a WASM runtime adapter if needed. Adapters convert external data to domain structures and vice versa.
    
- **Application (Orchestration) Layer:** (Sometimes combined with domain in simpler projects, but we'll define it for clarity.) This layer coordinates use cases and high-level workflows. It might contain services or use-case facades that the outside world calls to execute domain logic through ports. In a message-driven app, this could be where we subscribe to topics and call domain logic when messages arrive.
    
- **Entrypoint (Edge) Layer:** The top-level executables or deployment-specific code. For example, a `main.rs` that starts the app, sets up config, and in an edge scenario, possibly the WASM module's entry function. Also scripts or glue to run in different environments (like a local CLI vs. edge WASM host).
    
- **Shared/Utilities (Cross-cutting):** Utility modules (e.g., logging setup, common types) that do not depend on business logic and can be used across layers carefully.
    

We implement a _strict dependency rule_: **Inner layers (Domain) never depend on outer layers (Adapters, Entrypoint).** Outer layers can depend on inner layers. This enforces inversion of control via Ports:

- Domain defines interfaces (ports) that it needs, and possibly provides interfaces that outer layers can use.
    
- Adapters depend on domain to get trait definitions and possibly domain data structures (to convert to/from).
    
- Application/Entrypoint ties them together by injecting adapter implementations into domain logic (for example, passing a concrete NATS adapter where a `MessageBroker` trait is expected).
    

### Directory Structure and Module Organization

We organize code in the repository to reflect the architecture:

```
project-root/
├── Cargo.toml
├── src/
│   ├── domain/
│   │   ├── mod.rs            (maybe re-exports or high-level domain constructs)
│   │   ├── user.rs           (domain logic for user entity as example)
│   │   ├── order.rs          (another domain entity/module example)
│   │   └── ... (other domain modules)
│   ├── port/
│   │   ├── mod.rs            (list of trait definitions)
│   │   ├── messaging.rs      (e.g., defines trait MessageBroker)
│   │   ├── storage.rs        (e.g., defines trait StorageRepository)
│   │   └── ... (any other interface)
│   ├── adapter/
│   │   ├── mod.rs
│   │   ├── nats.rs           (implements MessageBroker for NATS JetStream)
│   │   ├── local_storage.rs  (maybe implements StorageRepository using local FS or a DB)
│   │   └── ... (other adapters like http_client.rs if needed)
│   ├── application/
│   │   ├── mod.rs
│   │   ├── handlers.rs       (subscribe to NATS subjects and call domain logic)
│   │   ├── commands.rs       (if we define commands/actions as orchestrators)
│   │   └── ... (other application logic, maybe scheduling, etc.)
│   ├── entrypoint/
│   │   ├── main.rs           (if running as native binary for tests or tools)
│   │   ├── lib.rs            (if compiling as WASM, possibly the lib that has _start function)
│   │   └── config.rs         (load env vars, config parsing)
│   └── shared/
│       ├── util.rs           (misc utilities)
│       └── types.rs          (common types, e.g., a DateTime wrapper or error types)
└── tests/                    (integration and contract tests)
    ├── integration_test.rs
    ├── contract_test.rs
    └── ...
```

(This is a conceptual structure; actual file naming can vary. In Rust, we might split crates as well, see below.)

**Crate structure:** If the project grows, we can split into multiple crates:

- `core` crate for domain + ports.
    
- `adapters` crate for infrastructure (depending on core).
    
- `app` crate for main, tying core and adapters.
    
- Possibly separate crate for WASM if needed (though Rust can compile the same code to WASM or native via feature flags).  
    However, for simplicity in a single repository, a module separation is fine, but enforce the dependency rules within it through careful code reviews (the compiler doesn’t enforce module-level cycles easily if all in one crate, but we can ensure not to call adapter from domain).
    

### Domain (Core) Layer Rules

- Domain code contains business logic and **only business logic**. This includes computations, validations, and state transitions defined by SPEC.md. For example, if SPEC says "orders cannot be fulfilled if expired," that rule is coded in domain (perhaps in an `order.rs` module or a domain service).
    
- **No External Calls:** Domain must not directly perform network calls, file I/O, or any OS interactions. It should be deterministic and side-effect free (given inputs, produce outputs/decisions). This makes it easier to test and run in WASM.
    
- **Data Structures:** Define the core data models here (as structs/enums). These should be technology-agnostic. E.g., an `Order` struct with fields, but it doesn't know _how_ it's stored or transmitted.
    
- **Pure Functions:** Where possible, implement logic as pure functions or methods that don't depend on context. If current time or random generation is needed, abstract it via a port (e.g., a `TimeProvider` trait in port, which an adapter can implement with actual clock).
    
- **Policies and Rules:** Complex domain rules spanning multiple entities can be organized as policy objects or domain services within this layer. But they still cannot call external systems; they may call port interfaces to fetch needed data.
    
- **Dependency:** Domain can depend on `shared` utilities, but not on `adapter` or `application`. Domain can depend on `port` module (if we define traits in a separate `port` module inside domain crate, it's essentially the same crate; but logically domain and port are separate concerns).
    
- In code terms, if someone tries to `use crate::adapter::...` inside `domain::...`, that’s a violation.
    
- **Testing:** Domain logic should be unit testable in isolation (we can test domain functions by just calling them with various inputs since no external coupling).
    

### Ports (Interface) Layer Rules

- **Define as Traits:** Each external interaction the domain needs is defined as a Rust trait in the `port` module. For example:
    
    - `trait MessageBroker { fn publish(&self, subject: &str, msg: &[u8]) -> Result<(), Error>; fn subscribe(&self, subject: &str, handler: Box<dyn Fn(Message) + Send>) -> ... }`
        
    - `trait UserRepository { fn save_user(&self, user: &User) -> Result<(), Error>; fn get_user(&self, id: UserId) -> Result<Option<User>, Error>; }`
        
    - These are just signatures; no implementation, no mention of NATS or Postgres, etc.
        
- **Domain Use of Ports:** Domain logic (or Application layer which orchestrates domain) will hold references (likely as trait objects or generics) to these ports to perform actions. For example, an order service in domain might have a `message_broker: Box<dyn MessageBroker>` to publish an event after processing.
    
- **No Implementation in Port Layer:** The port module should not have any logic, only interfaces (and maybe simple data type definitions for communication if needed, like an abstract `Message` structure if we want to decouple from NATS Message).
    
- **One Port per Concern:** Identify distinct concerns:
    
    - Messaging, Persistence, External APIs, Time, Random, etc., and define a port for each. Avoid overly broad interfaces.
        
    - If the application grows, this separation allows swapping out implementations (e.g., replace NATS with another broker, or use an in-memory stub for testing).
        
- **No Dependencies:** The port definitions should depend only on domain types or standard library. They should not pull in external crate types (like a NATS type) – adapters will handle conversion.
    
    - If using complex external data (like a Proto message struct), consider defining a domain-friendly struct and let adapter translate. Or at least keep external types behind the trait boundary.
        
- **Location:** Keep traits in a dedicated module (`src/port`). Optionally, some may reside in domain modules if very specific, but then re-export through port for clarity. The point is to logically group them.
    
- **Example:** A `StoragePort` trait might define methods for saving domain entities. Domain code calls `storage.save_order(order)`. The implementation (in adapter) might use an underlying database or even JetStream (if we use an event-sourcing approach storing events as stream).
    

### Adapters (Infrastructure) Layer Rules

- **Implement Traits:** For each port, provide one or more adapter implementations in `src/adapter/`. Examples:
    
    - `NatsMessageBroker` struct implements `MessageBroker`. It encapsulates a NATS client connection (maybe `async_nats::Connection`) and in `publish` method, it serializes messages (perhaps JSON) and publishes to NATS.
        
    - `JetStreamStore` implements `UserRepository` by writing to a JetStream stream or reading from it. Or if there's a simple KV store needed, JetStream has a Key-Value interface that could be used.
        
    - `SystemTimeProvider` implements `TimeProvider` trait by returning `std::time::SystemTime::now()` (for domain to use).
        
- **No Domain Logic:** Adapters should be thin. They **do not** make business decisions. They only transform and transmit data:
    
    - E.g., convert a `User` domain object to a JSON string and put it in a message, but not decide whether the user should be saved or not (domain decided that).
        
    - They handle errors from the infrastructure and convert them to domain-friendly `Error` variants.
        
- **External Dependencies:** Adapters can use external crates (this is where they belong). For instance, the NATS adapter will depend on the `nats` crate or `async-nats`. A database adapter might use `sqlx` or `surrealdb` crate, etc. These dependencies are kept out of domain.
    
- **Error Handling:** Adapters should map external errors to the common error type of the domain (we might have an `Error` enum in domain or use `anyhow` for simplicity internally but wrap it). This prevents leaking transport-specific errors upward.
    
- **No Cross-Adapter Calls:** One adapter generally shouldn’t call another adapter directly; if they need to coordinate, that is done via the domain or application layer.
    
    - Example: If a message triggers a DB save and then another message publish, the flow should be: Application layer receives message -> domain function does logic and calls repository port and message port -> adapters execute those calls. The NATS adapter doesn’t directly call the DB adapter; they each fulfill their port responsibilities.
        
- **Configuration:** Adapters may require configuration (e.g., NATS server URL, credentials file path). The Entrypoint layer (or application init) should pass config into adapter constructors. Adapters themselves can define `new()` that takes needed config values (but they shouldn’t, say, read environment variables internally; pass those in to keep things testable).
    
- **WASM Consideration:** Some adapters might not be usable in WASM (e.g., direct TCP connections in pure WASM aren’t allowed without host support). In an environment where the core logic runs in WASM, likely the adapters run on the host side. If so, our architecture might split:
    
    - The “adapter” for NATS actually runs outside WASM (like in the host runtime that triggers WASM functions).
        
    - The domain logic inside WASM might not directly call an adapter; instead, the host takes output and does the adapter job (like sending to NATS).
        
    - In the context of this policy, still define the trait and an adapter, but realize in actual deployment, the adapter might be a host component.
        
    - We might compile a version of the app for local testing where domain and adapter all run in one process.
        
    - The rule remains: domain/port code can be compiled to WASM (so it must not include any non-WASI-compatible code), and adapter code might be excluded in that build or included in host build only.
        
    - Use conditional compilation: e.g., `#[cfg(target_family = "wasm")]` to omit certain modules when building for WASM, or separate crate features like "host" vs "guest".
        
- **Example Implementation (Pseudo-code):**
    
    ```rust
    impl MessageBroker for NatsMessageBroker {
        fn publish(&self, subject: &str, data: &[u8]) -> Result<(), Error> {
            self.connection.publish(subject, data)
                .map_err(|e| Error::MessageBus(format!("NATS publish failed: {}", e)))
        }
        fn subscribe(&self, subject: &str, handler: Box<dyn Fn(Message) + Send>) -> Result<(), Error> {
            let sub = self.connection.subscribe(subject)
                .map_err(|e| Error::MessageBus("Sub fail"))?;
            // spawn a task to handle messages
            std::thread::spawn(move || {
               for msg in sub.messages() {
                  let domain_msg = Message { subject: msg.subject, data: msg.data };
                  handler(domain_msg); // call domain handler
               }
            });
            Ok(())
        }
    }
    ```
    
    The above shows the adapter handling subscription and on each message, calling a domain-provided handler (which might eventually call domain logic). It’s important that the adapter doesn’t itself contain business decisions; it just forwards data.
    

### Application (Orchestration) Layer Rules

- **Orchestrators/Use Case Handlers:** This layer is where specific use-cases are coordinated:
    
    - For message-driven app, this might not be extensive: basically the subscription handlers which receive messages and invoke domain logic.
        
    - If it were a web app, this is where controllers or services would live that call domain and then use adapters to respond.
        
- **Example:** We can have an `EventHandler` struct in `application::handlers` that holds references to the needed ports (like `MessageBroker` and `UserRepository`). It has methods like `handle_user_created(Message)`. This method would:
    
    1. Parse the message data into a domain `User` object.
        
    2. Call a domain service or directly perform domain logic (like validating user, etc.).
        
    3. Use the repository port to save the user.
        
    4. Use message port to maybe publish an acknowledgment or further events.
        
    
    - The application layer method orchestrates these steps, but minimal logic of its own.
        
- **Direct Domain Access:** Application layer is allowed to call domain code and to call adapter (via the port interfaces). It is essentially the wiring layer:
    
    - E.g., in `main.rs` (entrypoint layer, but combined with application in small apps), we might create an instance of `NatsMessageBroker`, create an instance of `EventHandler` with that and any other needed adapters, then subscribe to NATS and pass `EventHandler.handle_user_created` as the callback for `events.user.create` subject.
        
- **No Complex Logic:** Keep complex decisions in domain. Application might contain some simple conditional flows, but if it gets complex, consider moving that logic into domain (perhaps as a domain service coordinating multiple aggregates).
    
- **Transaction Management:** If we had transactions or cross-adapter consistency concerns (like update DB then send message), the application layer could manage that (ensuring steps all succeed or compensating if one fails). Rust doesn’t have a built-in transaction across systems, but design patterns like a saga might be implemented here if needed.
    
- **Edge Coordination:** In an edge context, if we have multiple WASM modules or instances, the application layer might also handle registration of those or partitioning tasks among them. However, given one app, likely not needed.
    
- **Separation from Entrypoint:** We differentiate application vs. entrypoint: application contains logic that could be reused in different deployment contexts, while entrypoint is the actual startup for a specific context. For example, if we have a `lib` that can run either in a server or as a Cloudflare Worker, the application layer could be in the lib, and entrypoint will either call lib’s run with an actual TCP NATS connection or, in WASM, the host triggers lib’s functions.
    

### Entrypoint and Edge Considerations

- **Main binaries:** We might have multiple binaries in Cargo (specified in Cargo.toml) for different runtime modes:
    
    - A normal binary for running as a standalone service (useful for local testing or if we ever run it as a server).
        
    - A build target for WASM (which might use the same code but with a different entry). For example, if using WASI, the entrypoint could be an `_start` that reads from stdin (like the Nex example in NATS docs).
        
- **Configuration Loading:** The entrypoint code is responsible for reading environment variables, config files, or command-line args. It should then instantiate the necessary components:
    
    - e.g., read `NATS_URL` env, instantiate `NatsMessageBroker` with that URL.
        
    - Possibly read `EDGE_NODE_ID` to use in identifying logs or subjects.
        
    - It should pass configuration down, not have other layers reading global state.
        
- **Starting Services:** In a server binary, entrypoint starts the runtime (Tokio runtime if using async), then starts subscriptions or schedule tasks. In WASM, the entrypoint might simply process one event (because in FaaS style, each invocation is separate).
    
- **Edge Deployment:** If deploying to an edge platform (like Cloudflare Workers or wasmCloud):
    
    - The entrypoint might be provided by the platform (e.g., Cloudflare expects certain exports). We ensure our compiled WASM meets those (the platform might call `call()` or `_start`).
        
    - In such a case, part of the adapter or entrypoint could be provided by that platform's SDK. For instance, wasmCloud uses message handlers defined via macros. We must integrate without breaking our structure: e.g., have a minimal shim that calls into our application layer.
        
- **File and Network Access:** On edge, direct file access might not be allowed. Our entrypoint or adapter must use the platform’s capabilities (like key-value store or secure storage).
    
    - Ensure any such calls are abstracted behind our ports, so we could, for example, implement the Storage port with Cloudflare Workers KV store if running there.
        
    - The domain and application layers remain unchanged regardless of running in full server or edge function environment.
        

### Dependency Constraints and Checks

To maintain the architecture integrity:

- **Module Privacy:** Mark modules or functions private where possible to avoid unintended usage. E.g., the adapter implementations might not need to be visible to domain code if they’re in separate crate or private mod.
    
- **Linter/Tool Enforcement:** Use tools or guidelines to prevent forbidden dependencies:
    
    - We could utilize clippy or cargo-deny with a `ban-build-deps` or similar feature (if any) or at least define in documentation "Do not call X from Y".
        
    - Code reviews (Audit Agent) will check for things like `use adapter::` in domain code.
        
    - If we had multiple crates, the Rust compiler naturally prevents cross-crate calls unless declared. E.g., domain crate doesn’t even include adapter crate as dependency, so it can’t call it.
        
- **Ports location:** If the project is single-crate, note that domain and adapters are in same crate, so Rust can call anything. We rely on convention and maybe tests:
    
    - Possibly have a test (or a deny rule) that ensures no direct dependency: one approach is to use `pub(crate)` and module structure to limit visibilities. For instance, place domain and port in one sub-crate or module, and adapters in another, though in one binary crate it’s tricky.
        
    - Alternatively, keep them separate as if crates by not exposing internals: e.g., domain code in `domain` mod doesn’t publicly expose internal details that adapter might need? Actually adapter will need domain types.
        
    - Perhaps simplest: we trust discipline and review for this. Or use doc comments to warn contributors.
        
- **Event Flow:** The architecture must be reflected in how events/messages flow:
    
    - NATS message arrives -> NATS adapter receives it (subscribe callback) -> calls an application layer handler (which is domain code or orchestrator) via the port interface or directly if arranged -> domain logic executes -> domain uses ports (which point to adapters) to do output actions -> e.g., adapter publishes a response or stores data.
        
    - At no point should the domain suddenly initiate a network call without going through port (which then goes to adapter).
        
    - At no point should an adapter try to determine business decisions (like reading a message and deciding not to call domain because of some logic).
        
- **Compile for WASM vs Native:** Use conditional compilation to maintain separation:
    
    - Mark any code that is not WASM-compatible with `#[cfg(not(target_arch = "wasm32"))]` or similar. For example, real NATS adapter might not work in WASM (no sockets); so we compile it only for non-wasm builds.
        
    - Conversely, provide a dummy or alternate implementation for WASM if needed (or the concept is that in WASM we don't actually include that module at all).
        
    - Domain and port should be target-agnostic (no `#[cfg]` needed ideally).
        
    - This way, building the WASM binary includes only domain + possibly a minimal adapter (like maybe serialization logic) but not the networking part.
        
    - The hosting environment provides actual networking in that case.
        
- **File Structure Compliance:** The code should stick to this structure. If a new functionality doesn’t clearly fit, discuss and possibly adjust the architecture, but do not randomly place code.
    
    - E.g., if need to add a new external service (say an API call to a weather service), one would add a new port trait (WeatherService) and an adapter for it (WeatherApiAdapter) in adapter module, then use it in domain or app as needed. **Do not** call the HTTP client directly from domain.
        
- **Example Violation and Resolution:** Suppose someone writes code in `domain/user.rs` that calls a function from the `nats` crate directly to publish a message. This violates the architecture:
    
    - The Audit Agent or a reviewer flags it: "Domain cannot use external crate `nats`. Move this call to an adapter."
        
    - The fix: create a `MessageBroker` trait (if not existing), implement a NATS adapter, have domain call `self.message_broker.publish(...).unwrap()` instead of directly calling `nats`.
        
    - This ensures testability (we can give a dummy broker in tests) and decoupling.
        

### Architectural Patterns and Conventions

- **Hexagonal Architecture (Ports & Adapters):** We essentially adopt hexagonal architecture. We avoid anemic models by allowing domain logic in entity methods or domain services. But often in Rust, we keep business logic in functions for clarity.
    
- **Event-Driven Design:** Because NATS/JetStream is at the core, we treat events as first-class. Each event type might correspond to a domain action. Designing around events:
    
    - Use consistent naming for event handlers (e.g., `on_user_created`).
        
    - Ensure idempotency where appropriate (if an event is processed twice, domain logic should handle gracefully or deduplicate via JetStream sequence).
        
    - The domain may have logic to avoid duplicate processing (like track an ID of processed events, though often JetStream can handle at-least-once with dedup by message ID).
        
    - Consider ordering: JetStream may deliver messages out of order in some cases (if using multiple subscribers). If ordering is important, design accordingly (maybe restrict to one logical subscriber or use message timestamps to sequence).
        
- **Scaling Up the Architecture:** If in the future the project is split into multiple microservices (e.g., separate binaries for different subjects), each microservice should follow the same internal layering. They would communicate via NATS between them. This policy can be applied to each, ensuring they have stable contracts (the messages between services).
    
- **Adapters for Testing:** You can have special adapters solely for test or dev:
    
    - e.g., an `InMemoryBroker` that implements `MessageBroker` by just logging or storing messages in a vector, for use in unit tests to verify "if domain calls publish, we capture it".
        
    - These test adapters reside either in test code or maybe in adapter module behind a test config flag.
        
    - This further shows the flexibility of the port/adapter approach.
        

In summary, the architecture mandates a **clean separation** of concerns and a one-directional dependency graph (no cyclic dependencies). This fosters a codebase where changes in one layer (e.g., swapping NATS for another transport) do not ripple into others, and domain logic remains highly testable and independent. The file and module structure should be kept tidy and reflective of these layers, making it easy for any new contributor or AI agent to find where certain code should reside. Architecture compliance is checked in every PR (by the Audit Agent or reviewer) as part of maintaining code health.

## Operations (CI/CD, Deployment, Monitoring, and Maintenance)

This section addresses the **Operational aspects** of the project – how we continuously integrate and deploy the application to the Edge environment, and how we monitor and manage it in production. Even for a one-person project, adopting robust DevOps practices ensures reliability and scalability akin to an enterprise setup. All operational steps are treated as code or configuration whenever possible, and they are documented and automated. Failure to follow these procedures can result in deployment errors or outages, which we treat seriously.

### Continuous Integration (CI) Pipeline

Our CI pipeline is configured to run on every push (particularly for PRs targeting main) and on a schedule for certain tasks. It performs the following stages (as partially discussed in [Prevention](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#prevention) and [Testing](https://chatgpt.com/c/689d1d10-36dc-8323-bfbb-b8fadd39ddf8#testing)):

1. **Checkout & Setup:** The CI environment checks out the repository. It sets up Rust (using the latest stable toolchain, or a specific stable version pinned for the project). For WebAssembly, it ensures the target `wasm32-wasi` is added (`rustup target add wasm32-wasi`). It also caches the Cargo build directory between runs to speed up builds (but invalidates cache when Cargo.lock changes).
    
2. **Build Stage:** Runs `cargo build --all` and `cargo build --target wasm32-wasi --release` to ensure both native and WASM builds pass. This stage catches compilation issues early.
    
3. **Lint & Format Stage:** In parallel, runs `cargo fmt --check` and `cargo clippy -- -D warnings`. These produce immediate feedback on style or lint issues.
    
4. **Test Stage:** As described, runs `cargo test`. If needed, also runs `cargo tarpaulin` for coverage (but sometimes coverage might be separate due to slowness, possibly on nightly builds).
    
    - For integration tests that need NATS, the CI pipeline will start a NATS server:
        
        - For example, in GitHub Actions, use a service container: `nats:latest` running on port 4222, or simply install `nats-server` binary and run it in background.
            
        - Ensure JetStream is enabled (NATS can auto-enable JetStream with a config or `--js` flag).
            
        - Set env `NATS_URL=nats://localhost:4222` for tests.
            
    - If any tests are tagged as requiring nightly or certain features, have separate job or skip those unless environment available. (Keep to stable for most.)
        
5. **Security Audit Stage:** Run `cargo audit` (and `cargo deny`) after tests. This ensures we don't fail builds for known issues until after confirming the code works. If this stage fails, it's a hard failure.
    
6. **Artifacts & Coverage (optional):** If the build is on main or a release branch, collect artifacts:
    
    - Build the WASM module (`.wasm` file) and maybe a compressed package of it.
        
    - Build a Docker image if our deployment uses containers (though for WASM, maybe not; but if we also have a sidecar or a native version).
        
    - Generate a coverage report and upload to a service (Codecov) if configured.
        
    - These steps are not gating (aside from maybe coverage threshold enforcement).
        
7. **Continuous Delivery Trigger:** If all the above pass on a main branch push (or a tagged release), trigger the deployment pipeline (detailed next).
    

**CI Failure Outputs:** We have configured CI such that if any step fails, it clearly prints the reason as described in earlier sections. We use annotations if possible (for instance, GitHub Actions can annotate lines in PR for clippy warnings/errors, which helps fix them faster).

**Required Checks Enforcement:** The branch protection is set such that the PR cannot be merged until CI passes all required jobs:

- Typically a job for build, one for tests, one for audit. Or we combine some, but logically all must pass.
    

**Speed and Feedback:**

- We parallelize independent steps (lint, build, test can run concurrently on separate containers).
    
- We aim for pipeline completion in e.g. < 5 minutes for typical changes (unit tests are fast; integration maybe slower if waiting on timeouts).
    
- We have a nightly pipeline that might do more exhaustive things: run fuzz tests for an hour, run full coverage, etc., not required for each PR but gives periodic quality checks.
    

### Continuous Deployment (CD) Process

Once changes are merged into `main`, our goal is to deploy them to the edge environment in an automated fashion, with appropriate safety checks (canary releases, etc.). The CD process is as follows:

1. **Versioning & Tagging:** Every merge to main is either a release candidate or immediately deployable. We automatically bump version numbers according to the changes:
    
    - If only fixes/minor features (no contract breaks), bump minor or patch version. If a contract break (major version), we likely orchestrated that as separate branch, but anyway, version in Cargo.toml and any API version constant should have been updated.
        
    - Use Conventional Commit messages or PR labels to determine version bump. The CD pipeline could run a version bump script or confirm the version is updated properly in code.
        
    - Optionally, create a Git tag like `v1.2.3` on the commit for traceability.
        
2. **Build Artifacts for Release:**
    
    - Compile the final artifacts: e.g. `cargo build --release --target wasm32-wasi` producing `app.wasm` (the WebAssembly module to deploy).
        
    - If we also deploy a native component (not sure if needed for edge, but perhaps a sidecar or just for reference), compile that too.
        
    - If packaging in a container, build a minimal container image. Perhaps the container might just include a Wasmtime runtime and the WASM module if deploying to a generic container platform. Alternatively, if using a specific edge platform like wasmCloud, the deployment might be via their tooling.
        
    - Ensure artifacts are reproducible and deterministic as possible (lockfile ensures same deps).
        
3. **Deploy to Edge Environment:**
    
    - Depending on our edge infrastructure, this step varies:
        
        - **If using a platform like Cloudflare Workers:** Use their CLI (e.g., `wrangler publish`) to upload the WASM, along with configuration (routes, KV bindings, etc.).
            
        - **If using wasmCloud:** Use `wash` CLI or the control interface to deploy the actor module to the lattice (with NATS as the control plane).
            
        - **If using custom infrastructure (e.g., our own distributed nodes):** Possibly have a script to distribute the WASM file to all nodes and restart them. This could be an SSH or Ansible job or using a container orchestrator:
            
            - For instance, build a Docker image that wraps the WASM in wasmtime, then use Kubernetes to rolling-update a DaemonSet or Deployment on edge nodes.
                
        - **If using a self-managed NATS + WASM processes:** e.g., each edge node runs a small host program that loads the latest WASM: we might implement a mechanism:
            
            - The CD could publish the new WASM to a JetStream stream (like a versioned blob).
                
            - Edge nodes subscribe to updates (this is something NATS can do: send notifications to nodes to load new code).
                
            - But simpler: use an SSH script to each node: stop current process, replace WASM file, start new process.
                
    - We prefer a rolling or blue-green strategy to avoid complete downtime:
        
        - Example rolling: Update one node at a time (if we have multiple edge instances). Wait for health check pass, then next.
            
        - Blue-green: deploy new version to a parallel set of nodes, test, then switch traffic. With NATS, this might mean new nodes joining the cluster and old unsubscribing after a cutover.
            
    - If only one instance (not typical in edge concept, but if early stage), then a short downtime might occur on restart. We should aim to minimize startup time (WASM can init quickly).
        
4. **Post-Deploy Verification:** After deployment, run quick smoke tests:
    
    - Possibly a small script that sends a test message through NATS and checks for an expected response from the newly deployed code.
        
    - Or use built-in health endpoints: if we had a heartbeat message type or a status query in the system, trigger it.
        
    - Ensure that the new version registers as healthy (maybe each node can publish a "startup ok" message).
        
    - The CD pipeline waits for confirmation. If something is wrong (no confirmation or test fails), it triggers a rollback.
        
5. **Rollback Plan:** Always have a rollback ready:
    
    - The previous stable version of the WASM module is kept. If the new version is failing (e.g., triggers alerts or fails health check), the pipeline or the operator can redeploy the old version.
        
    - If using a platform, this might be as easy as re-pointing to old version or re-running the deployment with the old artifact.
        
    - Data compatibility: ensure that any data changes are backward compatible or handled, so the old version can still run on current data if reintroduced.
        
    - The Operations procedure should document how to invoke rollback (maybe a script `deploy.sh rollback vX.Y.Z`).
        
6. **Notifications:** Upon successful deployment, the pipeline (or Reporting Agent) sends a notification (for example, a message to a Slack channel or simply logs in console/email to dev) that deployment succeeded with version number and timestamp. If failed or rolled back, immediate alert to fix the issue (with logs of failure).
    

### Deployment Environment Details

- **NATS Cluster:** The system relies on a NATS server (or cluster) with JetStream. In production, we run NATS in a clustered, highly-available configuration (e.g., 3 or 5 servers distributed perhaps globally or per region).
    
    - JetStream streams might be configured with replication for HA.
        
    - The app (WASM or not) connects to NATS with failover (the NATS client typically can get multiple server addresses).
        
    - The deployment should ensure NATS credentials and configuration are properly set on each node or environment (for Workers or wasmCloud, likely integrated).
        
- **Edge Nodes:** These could be actual servers or instances in various regions. Each runs the application logic (as WASM possibly).
    
    - If using wasmCloud or a similar orchestrator, those handle scheduling the actor (our module) to nodes.
        
    - If custom, perhaps we maintain a static list of nodes.
        
    - Scalability: we should be able to add more nodes if load increases. Document how to do that (e.g., launch a new VM/container with the app, it auto-connects to NATS cluster, starts subscribing).
        
- **Configuration Management:** Use environment variables for configuration (like `NATS_URL`, `NATS_CREDS` for credentials, etc.) on each node or in orchestrator. We store non-secret configs in a version-controlled file for reference but actual secrets in secret stores as mentioned.
    
- **WASM specifics:** The WASM module should be optimized for size and performance:
    
    - Use `wasm32-wasi` target and strip symbols, maybe run `wasm-opt` to optimize size.
        
    - The CI can include a step to run `wasm-snip` or `wasm-opt -Os` to reduce size of `.wasm` before deploying (especially important if deploying to edge where size affects cold start).
        
    - If multiple modules or services, consider using the Component Model or linking, but that’s advanced; currently likely single module.
        
    - Keep an eye on WASM execution limits (some platforms limit CPU time, memory for WASM).
        
- **State and Data:** If the application uses JetStream for persistent data, ensure that is configured with adequate disk and memory. If any local caching on nodes, be aware an edge node restart might lose it, but presumably state is in JetStream.
    

### Monitoring and Alerting

To run in production reliably, we put in place monitoring of various aspects:

- **Application Logging:** The app (domain or application layer) should produce structured logs for important events:
    
    - Use a logging crate (like `log` with `env_logger` or `tracing` crate for structured data).
        
    - At startup, log version and configuration summary (but not secrets).
        
    - Log at INFO for normal significant events (e.g., "Processed OrderCreated event for order 12345"), at DEBUG for verbose troubleshooting (can be enabled when needed), at WARN/ERROR for issues.
        
    - Ensure all error cases in code log something when an operation fails (unless it's expected and handled).
        
    - In an edge environment, logs may go to standard out (captured by platform) or to a log service.
        
    - We may integrate with a log aggregator (ELK stack, Splunk, etc.) if available. If not, at least have logs accessible (like `kubectl logs` if on K8s, or Workers has built-in log console).
        
- **Metrics:** Collect metrics for critical parameters:
    
    - Number of messages processed, per subject, per unit time.
        
    - Processing latency for each message (time from receive to processed).
        
    - Errors count (how many messages failed processing or were invalid).
        
    - Resource usage: memory and CPU usage of the WASM instances if possible. Some platforms give this (e.g., cloudflare workers have limited CPU time metrics).
        
    - NATS server metrics: subject backlog lengths, JetStream disk usage, etc.
        
    - We can instrument code with something like `metrics` crate or `opentelemetry` to emit metrics. If using Prometheus, we might have to expose an endpoint or push metrics. On an edge function, might not run a server; maybe push metrics to a collector via NATS or an HTTP call.
        
    - If using wasmCloud, it has its own monitoring. If using custom, perhaps each node has a sidecar for metrics or we rely on NATS monitoring (NATS has monitoring endpoints).
        
- **Health Checks:** Implement a health-check mechanism:
    
    - If the app is a long running service, an HTTP health endpoint or a periodic self-check. But for WASM FaaS style, it's invoked per request, so maybe no persistent process to health-check.
        
    - However, ensure NATS connectivity: the app should detect if it gets disconnected and try to reconnect. Monitor if it stays disconnected beyond X seconds.
        
    - For cluster health: NATS server provides monitoring endpoints (HTTP /varz, etc.). We can either rely on external monitors for NATS or incorporate something.
        
- **Alerting Rules:** Define triggers that will send an alert to the developer (or an ops channel):
    
    - If **service crashes or becomes unresponsive**: e.g., if an edge node stops consuming messages (can be detected if JetStream backlog grows beyond a threshold, meaning consumers might be down).
        
    - If **error rate** in processing messages exceeds a threshold: e.g., more than 5% of messages result in an error (maybe due to unexpected input or bug).
        
    - If **latency** goes high: if messages are taking too long to process or to be acknowledged, could indicate performance issues.
        
    - If **resource exhaustion**: memory usage near limit (especially important for WASM which might have memory cap), or if CPU usage saturates consistently.
        
    - If **JetStream nearing limits**: e.g., storage at >80% capacity, or a stream has many unprocessed messages indicating a slowdown.
        
    - **Security alerts**: e.g., if we detect an authentication failure repeatedly (could indicate someone trying to send unauthorized messages) or if any integrity check fails.
        
    - For each of these, have monitoring system send an email or push notification. If not available, at least log them loudly and the Reporting Agent can highlight them for manual check daily.
        
- **Dashboards:** (If tools available) Create dashboards for message throughput, error rate, etc., to visually monitor the system over time. This can help in capacity planning and early anomaly detection.
    

We should use existing solutions as much as possible (Prometheus + Grafana, etc., or whatever is suitable). For a solo dev, even simple scripts that check logs or metrics periodically and send SMS on issues could be enough, but since we aim for enterprise-like, we describe it thoroughly.

### Incident Response and Recovery

Despite best efforts, incidents may happen (outages, data issues). We define procedures for responding:

- **On-Call:** As a solo developer, you are essentially always on-call. However, set up alerts at reasonable thresholds so you're not overwhelmed. Use a phone notification for critical alerts.
    
- **Runbooks:** Document common failure scenarios and what to do:
    
    - e.g., "If NATS cluster is down: steps to restart it or failover to backup cluster".
        
    - "If a bug in new release causes crashes: steps to rollback (and which commit to rollback to)".
        
    - "If data in JetStream is corrupted or lost: steps to restore from backup".
        
- **Backups:** If applicable, schedule backups for any stateful data. JetStream can be configured to mirror streams or one can use the `nats stream snapshot` feature to backup stream data to a file. Document how often and where backups are kept. Also, configuration (like if our system has any config DB or such) should be backed up.
    
- **Testing Recovery:** Now and then, simulate a failure (like kill one edge node and see if system continues; or simulate a NATS server failure) to verify our high-availability works. The system should ideally be built to be resilient:
    
    - Multiple edge nodes ensure one down doesn't stop service (NATS will route messages to others).
        
    - NATS cluster ensures one server down doesn’t lose messages (if using cluster + RAFT for JetStream).
        
    - The app should be stateless (except JetStream) so redeploying or moving it doesn’t lose anything.
        
- **Post-Incident:** After an incident, do a root cause analysis:
    
    - Identify what went wrong (bug, unexpected input, infra issue, etc.).
        
    - Fix the root cause (code fix, or infra config change).
        
    - Update tests to cover that scenario if it was a gap (so that it cannot happen again unnoticed).
        
    - Update this policy or runbooks if something was missing (e.g., add a monitoring rule if we missed detecting it).
        
    - Communicate (even if just to a log or diary for the project) what happened and resolution, to maintain history.
        

### Scalability and Performance

We plan for scaling the system as usage grows:

- **Scaling Out:** Since the system is event-driven, horizontal scaling is straightforward:
    
    - Deploy more edge instances running the WASM logic to handle increased message volume. NATS supports load balancing via queue groups for consumers: we can configure all instances to join the same queue group for a subject so that messages are distributed among them.
        
    - Ensure that adding a new instance doesn’t require code changes: it should auto-register to NATS and start receiving work.
        
    - Watch out for ordering if we scale: if order matters, we might need to pin certain messages to certain consumers (like sharding by key) – consider using queue groups appropriately or design messages to be independent.
        
- **Scaling NATS/JetStream:** If message throughput or stored data grows:
    
    - NATS can cluster. We can add nodes to the NATS cluster. JetStream streams can be scaled by sharding (distributing keys to different streams by some partition key). That requires planning in advance if extremely high volume, but likely not needed unless we know the data pattern.
        
    - NATS has a limit per stream for messages or bytes; monitor those, and configure rotation or clustering if needed.
        
- **Bottlenecks:** Identify potential bottlenecks:
    
    - The WASM execution speed: maybe heavy computations could be a bottleneck. If so, consider optimizing critical code in Rust (which is already quite fast, but algorithmic improvements or parallelism if possible).
        
    - If one message triggers heavy CPU, it might stall that worker – but multiple instances can help if tasks can be parallel.
        
    - Network: ensure NATS network latency is low by deploying servers close to edge nodes (maybe each region has a NATS server). Use NATS gateways or superclusters to connect regions if needed, so that events can flow globally but processed locally when possible.
        
    - JetStream disk I/O: if writing many events, ensure using SSD and enough IOPS on those servers.
        
- **Performance Testing:** We should do load tests to understand how many messages per second the system can handle and where it breaks. Use a tool or custom script to publish a high volume of events and see if processing keeps up.
    
    - Do this for increasing number of edge nodes to see linear scaling or any contention (maybe on a shared resource).
        
    - Monitor memory usage – ensure no memory leak (Rust should free most, but long-living processes or large caches might leak if not managed).
        
- **Limits and Throttling:** If clients (or external producers) can flood the system, we might need throttling:
    
    - Use JetStream max ingress limits or consumer max ack pending to avoid unlimited backlog.
        
    - The application could detect if it’s overwhelmed (queue length growing) and either shed load (e.g., drop non-critical messages) or autoscale (if using K8s, use HPA triggers on CPU or queue length).
        
    - If applicable, implement backpressure: e.g., if an event triggers an outgoing event storm, maybe limit that.
        
- **Edge Specific:** If using a platform like Cloudflare Workers, be aware of their CPU time limits per invocation. For long tasks, might need to break work or use Durable Objects, etc. Keep each event handling within those limits.
    
    - For wasmCloud, consider actor concurrency and number of hosts.
        

### Maintenance and Operations Tasks

- **Regular Updates:** Keep Rust toolchain and dependencies up to date. Perhaps schedule a monthly task for the Generation or Audit Agent to open a PR updating crates (like what Dependabot does, but we can integrate that or do manually). Run tests to ensure nothing breaks.
    
- **Infrastructure Maintenance:** Update NATS server versions as they release security or feature updates. Do this carefully (upgrade one node at a time if cluster).
    
- **Cost Monitoring:** If running on a cloud platform, watch resource usage so costs don’t skyrocket. Optimize usage (e.g., scale down at off-peak times if possible, or use smaller instances).
    
- **Documentation:** Maintain good ops docs (possibly outside this prompt scope) – but important for if someone else joins or if you have to step away, so someone can pick it up.
    
- **Compliance:** If any data governance or compliance (GDPR etc.) is needed, incorporate that into operations (like ability to delete user data from streams if requested, logging access, etc.). This might not be needed now, but keep in mind.
    

**Final Note:** The Operations guidelines ensure that the software, once built according to spec and quality in earlier sections, is actually delivered to users reliably. All these steps are integrated as code (in CI/CD configs, in scripts, in agent logic) so that nothing is left to ad-hoc processes. By following them, even a single developer can achieve a robust DevOps cycle with continuous delivery, quick issue detection, and scalable architecture, comparable to a professional team’s output.