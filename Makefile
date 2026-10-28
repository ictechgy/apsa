.PHONY: install-local install-skill test benchmark release export-release fixtures-binary fixtures-runtime

UV_RUN = uv run --locked --extra dev
RELEASE_OUT ?= dist/apsa-local-release
BENCHMARK_OUT ?= $(shell python3 -c 'import tempfile; print(tempfile.mkdtemp(prefix="apsa-benchmark-") + "/evidence")')

install-local:
	uv tool install --editable . --force --python 3.12.13 --constraints requirements-release.txt

install-skill:
	$(UV_RUN) apsa skill install

test:
	$(UV_RUN) pytest -q
	$(UV_RUN) ruff check apsa src benchmarks scripts quaygate/cli.py quaygate/indicators.py tests/test_audit.py tests/test_benchmark.py tests/test_binary_analysis.py tests/test_foundations.py tests/test_intel.py tests/test_intel_product.py tests/test_interfaces.py tests/test_jobs.py tests/test_policy.py tests/test_runtime.py tests/test_source_analysis.py tests/test_unified.py tests/test_product_review.py tests/test_release_hardening.py tests/test_evidence106.py tests/test_workflows11.py tests/test_real_world_hardening.py tests/test_coverage_extension.py tests/test_next_hardening.py tests/test_dependency_evidence.py tests/test_parser_depth.py tests/test_intel_history.py tests/test_adoption.py tests/test_agent_verification.py tests/test_platform_checks.py tests/test_sbom.py tests/test_mastg_demos.py tests/test_ingest.py tests/test_checklists.py tests/test_detection_breadth.py tests/test_fpfn_eval.py tests/test_large_inputs.py tests/test_fresh_benchmark.py tests/test_dependency_cache_window.py tests/test_hybrid_callable_identity.py tests/test_osv_pagination_recovery.py tests/test_claim_verification_scope.py tests/test_apks_provenance.py tests/test_objc_binding_scope.py tests/test_runtime_cancellation.py tests/test_osv_alias_collisions.py tests/test_remaining_integration.py tests/test_finding_followup.py tests/test_followup_interfaces.py tests/test_followup_benchmark.py tests/test_native_flow_scaling.py tests/test_parser_resource_diagnostics.py tests/test_collect_holdout_reports.py tests/test_sensitive_log_boundaries.py tests/test_namespace_url_indicators.py tests/test_dex_budget_coverage.py
	$(UV_RUN) ruff format --check apsa src benchmarks scripts quaygate/cli.py quaygate/indicators.py tests/test_audit.py tests/test_benchmark.py tests/test_binary_analysis.py tests/test_foundations.py tests/test_intel.py tests/test_intel_product.py tests/test_interfaces.py tests/test_jobs.py tests/test_policy.py tests/test_runtime.py tests/test_source_analysis.py tests/test_unified.py tests/test_product_review.py tests/test_release_hardening.py tests/test_evidence106.py tests/test_workflows11.py tests/test_real_world_hardening.py tests/test_coverage_extension.py tests/test_next_hardening.py tests/test_dependency_evidence.py tests/test_parser_depth.py tests/test_intel_history.py tests/test_adoption.py tests/test_agent_verification.py tests/test_platform_checks.py tests/test_sbom.py tests/test_mastg_demos.py tests/test_ingest.py tests/test_checklists.py tests/test_detection_breadth.py tests/test_fpfn_eval.py tests/test_large_inputs.py tests/test_fresh_benchmark.py tests/test_dependency_cache_window.py tests/test_hybrid_callable_identity.py tests/test_osv_pagination_recovery.py tests/test_claim_verification_scope.py tests/test_apks_provenance.py tests/test_objc_binding_scope.py tests/test_runtime_cancellation.py tests/test_osv_alias_collisions.py tests/test_remaining_integration.py tests/test_finding_followup.py tests/test_followup_interfaces.py tests/test_followup_benchmark.py tests/test_native_flow_scaling.py tests/test_parser_resource_diagnostics.py tests/test_collect_holdout_reports.py tests/test_sensitive_log_boundaries.py tests/test_namespace_url_indicators.py tests/test_dex_budget_coverage.py
	$(UV_RUN) pyright apsa src benchmarks scripts quaygate/cli.py quaygate/indicators.py tests/test_audit.py tests/test_benchmark.py tests/test_binary_analysis.py tests/test_foundations.py tests/test_intel.py tests/test_intel_product.py tests/test_interfaces.py tests/test_jobs.py tests/test_policy.py tests/test_runtime.py tests/test_source_analysis.py tests/test_unified.py tests/test_product_review.py tests/test_release_hardening.py tests/test_evidence106.py tests/test_workflows11.py tests/test_real_world_hardening.py tests/test_coverage_extension.py tests/test_next_hardening.py tests/test_dependency_evidence.py tests/test_parser_depth.py tests/test_intel_history.py tests/test_adoption.py tests/test_agent_verification.py tests/test_platform_checks.py tests/test_sbom.py tests/test_mastg_demos.py tests/test_ingest.py tests/test_checklists.py tests/test_detection_breadth.py tests/test_fpfn_eval.py tests/test_large_inputs.py tests/test_fresh_benchmark.py tests/test_dependency_cache_window.py tests/test_hybrid_callable_identity.py tests/test_osv_pagination_recovery.py tests/test_claim_verification_scope.py tests/test_apks_provenance.py tests/test_objc_binding_scope.py tests/test_runtime_cancellation.py tests/test_osv_alias_collisions.py tests/test_remaining_integration.py tests/test_finding_followup.py tests/test_followup_interfaces.py tests/test_followup_benchmark.py tests/test_native_flow_scaling.py tests/test_parser_resource_diagnostics.py tests/test_collect_holdout_reports.py tests/test_sensitive_log_boundaries.py tests/test_namespace_url_indicators.py tests/test_dex_budget_coverage.py

benchmark:
	$(UV_RUN) python benchmarks/fresh.py --out "$(BENCHMARK_OUT)" --check-regression-contract

export-release:
	uv export --locked --no-dev --no-emit-project --no-header --quiet --output-file requirements-release.txt

release:
	$(UV_RUN) python scripts/release.py --out "$(RELEASE_OUT)"

# Explicit SDK-dependent fixture rebuilds; ordinary tests never install/boot apps.
fixtures-binary:
	@test -n "$(ANDROID_SDK)" || (echo "Set ANDROID_SDK to the installed SDK directory" >&2; exit 2)
	$(UV_RUN) python tests/fixtures/binary_analysis/build.py --sdk "$(ANDROID_SDK)"

fixtures-runtime:
	@test -n "$(FIXTURE_OUT)" || (echo "Set FIXTURE_OUT to a new local fixture directory" >&2; exit 2)
	$(UV_RUN) python tests/fixtures/runtime/build.py --platform "$(or $(FIXTURE_PLATFORM),android)" --out "$(FIXTURE_OUT)" $(if $(ANDROID_SDK),--sdk "$(ANDROID_SDK)",)
