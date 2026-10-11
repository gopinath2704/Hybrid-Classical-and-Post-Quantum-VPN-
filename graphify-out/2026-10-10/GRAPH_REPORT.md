# Graph Report - Hybrid-Classical-and-Post-Quantum-VPN-  (2026-10-10)

## Corpus Check
- 61 files · ~139,840 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 25 file(s) not represented in the graph (top: (none) 12, .service 4, .toml 3)

## Summary
- 2097 nodes · 4899 edges · 116 communities (80 shown, 36 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 360 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `e719c4c0`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- HandshakeSession
- doctor_run
- KeyManager
- PQSignatureProvider
- SessionKeyStore
- TestPQCProvider
- TestKeyManager
- CookieProtector
- PQVPN Deployment
- AccountAPIConfig
- MainWindow
- HybridKEM
- client.py
- FakeSocket
- run_pqvpn.py
- reproduce.sh
- test_eval_harness.py
- TUNInterface
- _pack_header
- account_api.py
- HandshakeBenchmark
- NetworkQualityMonitor
- ClientService
- test_accounts.py
- create_app
- test_runtime.py
- _MockInsecureSigProvider
- ProfileError
- run_flood_trial
- AccountAPIError
- get_crypto_status
- .__init__
- test_onboarding.py
- IPCClient
- ._request
- test_crypto_protocol.py
- benchmarks.py
- AuthorizedClients
- kemtls.py
- AccountSession
- ipc_recv
- IPPool
- PQCProvider
- fingerprint
- _MockInsecurePQCProvider
- bearer
- Desktop Milestone 3 managed installation
- VPNServer
- ClientStatus
- Path
- generate_tables.py
- PacketOverheadAnalyzer
- test_account_api.py
- MTUMonitor
- test_deployment.py
- pqvpn
- PQ-VPN Evaluation — Validity Report
- AccountStore
- UserRecord
- Security Audit — 2026-09-05
- TestAccountGUI
- provision_eval_host.sh
- AccountClient
- ThroughputBenchmark
- _IPCWorker
- PowerButton
- network.py
- test_networking.py
- accounts.py
- ECCProvider
- ._connection
- app
- PQCUnavailableError
- identity.py
- results-summary/README.md
- Auto-routing rules
- PQVPN Design
- PQ-VPN
- TestECCProvider
- _device_setup
- datetime
- _sanitized_message
- test_udp_bind_failure_cleans_every_resource
- Remaining Steps for the Paper / Artifact
- measure_throughput.py
- Reproducibility Artifact
- fail
- BoundedRateLimiter
- test_real_namespace_tunnel
- 2. Results tables
- PQ-VPN Evaluation Write-Up
- namespace_vpn.sh
- run_pqvpn_net.sh
- 1. Headline findings
- Re-run Commands — producing the PENDING cells on a capable host
- Quick start
- /dev — Toolchain Status & Override
- Encrypted frame
- SourceRateLimiter
- verify_formal.sh
- test_native_authenticated_session_records
- bench_netem.sh
- Milestone 3 live validation: Omarchy client + Ubuntu VM
- netem_profiles.sh
- install-liboqs.sh
- server-network.sh
- Legacy explicit-TOML client setup
- Pre-VPS Validation Handoff

## God Nodes (most connected - your core abstractions)
1. `HandshakeError` - 90 edges
2. `MainWindow` - 79 edges
3. `fingerprint()` - 64 edges
4. `AccountStore` - 60 edges
5. `ClientService` - 53 edges
6. `ClientStatus` - 45 edges
7. `AccountClient` - 45 edges
8. `HybridKEM` - 45 edges
9. `VPNClient` - 43 edges
10. `PQCProvider` - 41 edges

## Surprising Connections (you probably didn't know these)
- `A-03 — Legacy/ambiguous PQC selection and unsafe wire choices` --references--> `PQCProvider`  [INFERRED]
  docs/security_audit.md → crypto/hybrid_crypto.py
- `2026-09-05 focused follow-up findings` --references--> `ClientNetwork`  [INFERRED]
  docs/security_audit.md → vpn/runtime.py
- `IPC boundary` --references--> `VPNClient`  [INFERRED]
  docs/design.md → vpn/runtime.py
- `Packaging foundation` --references--> `PQCUnavailableError`  [INFERRED]
  docs/deployment.md → crypto/hybrid_crypto.py
- `A-13 — Handshake parsers accept inconsistent/trailing data` --references--> `_unpack_header()`  [INFERRED]
  docs/security_audit.md → handshake/kemtls.py

## Import Cycles
- None detected.

## Communities (116 total, 36 thin omitted)

### Community 0 - "HandshakeSession"
Cohesion: 0.06
Nodes (16): D6: Data-plane implementation scope, A-01 — Server is not authenticated, _compute_finished_mac(), derive_schedule(), derive_schedule_mldsa(), derive_schedule_v3(), _derive_secrets(), _expand() (+8 more)

### Community 1 - "doctor_run"
Cohesion: 0.09
Nodes (26): test_doctor_production_scope(), test_doctor_reports_privileged_code_failure(), test_privileged_intermediate_symlink_is_audited(), test_privileged_interpreter_symlink_target_and_parent(), test_privileged_missing_interpreter_fails(), test_privileged_root_owned_code_and_venv_pass(), command(), doctor_run() (+18 more)

### Community 3 - "PQSignatureProvider"
Cohesion: 0.13
Nodes (10): PQSignatureProvider, _make_mldsa_endpoints(), ClientHelloMLDSA, KEMTLSClientMLDSA, KEMTLSServerMLDSA, test_mldsa_message_sizes(), test_mldsa_transcript_tampering_rejected(), test_mldsa_unauthorized_client_rejected() (+2 more)

### Community 4 - "SessionKeyStore"
Cohesion: 0.05
Nodes (4): _secure_zero(), SessionKeyStore, SessionRecord, TestSessionKeyStore

### Community 8 - "CookieProtector"
Cohesion: 0.15
Nodes (9): CookieProtector, test_cookie_accepted_just_before_and_after_rotation(), test_cookie_bad_length_rejected(), test_cookie_no_crash_at_boot_time(), test_cookie_protector_rotation(), test_cookie_protector_round_trip(), test_cookie_rejected_after_two_rotations(), test_cookie_wrong_ip_rejected() (+1 more)

### Community 9 - "PQVPN Deployment"
Cohesion: 0.09
Nodes (22): Current validation record, Current validation record, Disposable root namespace gate, DNS policy, Exact tested dependencies, Firewall policy and subnet selection, Install and provision, then diagnose, Linux VPS deployment gate (+14 more)

### Community 10 - "AccountAPIConfig"
Cohesion: 0.21
Nodes (10): test_dedicated_config_loads_relative_paths_and_rejects_unknown_values(), test_login_rate_limit_is_source_scoped(), test_login_rate_limit_returns_429_retry_after_and_is_identifier_scoped(), test_registration_limiter_is_separate_from_login_limiter(), test_remote_or_implicit_cleartext_bind_fails_closed(), test_tls_files_are_required_regular_and_private_key_is_private(), AccountAPIConfig, AccountAPIConfigError (+2 more)

### Community 11 - "MainWindow"
Cohesion: 0.08
Nodes (5): format_duration(), _launch_gui(), main(), MainWindow, truncate_fingerprint()

### Community 12 - "HybridKEM"
Cohesion: 0.09
Nodes (4): HybridKEM, HybridKeyBundle, TestHybridKEM, tampered()

### Community 13 - "client.py"
Cohesion: 0.08
Nodes (5): account_ux_state(), SessionState, _socket_path(), craft_clienthello(), TestAccountUXState

### Community 15 - "run_pqvpn.py"
Cohesion: 0.13
Nodes (13): evaluate_suite(), _liboqs_version(), main(), measure_encrypt_throughput(), measure_handshakes_per_sec(), measure_memory_per_session(), require_native_pqc(), run_handshake() (+5 more)

### Community 17 - "test_eval_harness.py"
Cohesion: 0.11
Nodes (12): bootstrap_ci(), generate_summary(), group_data(), test_benchmarks_pqc_guard_rejects_mock(), test_bootstrap_ci_deterministic(), test_bootstrap_ci_known_sample(), test_bootstrap_ci_single_value(), test_bootstrap_ci_tight_sample() (+4 more)

### Community 18 - "TUNInterface"
Cohesion: 0.12
Nodes (4): connectivity(), IPv6Guard, preflight(), TUNInterface

### Community 19 - "_pack_header"
Cohesion: 0.07
Nodes (21): A-13 — Handshake parsers accept inconsistent/trailing data, ClientHello, ClientHelloV3, ClientKeyExchange, ClientKeyExchangeMLDSA, ClientKeyExchangeV3, _fields(), _fixed() (+13 more)

### Community 20 - "account_api.py"
Cohesion: 0.12
Nodes (6): BodyLimitMiddleware, DeviceBindRequest, LoginRequest, main(), RegisterRequest, run()

### Community 21 - "HandshakeBenchmark"
Cohesion: 0.12
Nodes (6): HandshakeBenchmark, HandshakeMetric, SuiteSummary, _write_suite_csv(), test_handshake_benchmark_output(), test_benchmarks_cpu_split()

### Community 22 - "NetworkQualityMonitor"
Cohesion: 0.11
Nodes (4): test_quality_metrics_jitter_loss_reset(), test_quality_rolling_window(), NetworkQualityMonitor, QualitySnapshot

### Community 23 - "ClientService"
Cohesion: 0.09
Nodes (4): ClientService, sanitize_error(), test_error_sanitization_is_bounded_and_redacts_secrets(), TestClientService

### Community 24 - "test_accounts.py"
Cohesion: 0.11
Nodes (27): `POST /auth/register`, _cli(), public_identity(), raw_connection(), review(), store(), test_account_mutations_never_change_vpn_authorization(), test_add_and_list_multiple_devices() (+19 more)

### Community 25 - "create_app"
Cohesion: 0.15
Nodes (20): test_registration_never_changes_vpn_authorization(), test_successful_login_resets_failed_attempts(), create_app(), bind_device(), database_error(), internal_error(), list_devices(), login() (+12 more)

### Community 26 - "test_runtime.py"
Cohesion: 0.09
Nodes (35): FrameType, test_fail_policy_rejects_before_tun_or_routing(), connected(), FakeTun, ipv4(), test_authenticated_keepalive_prevents_idle_expiry(), test_automatic_rekey_short_interval(), test_client_rekey_protocol_uses_control_domain() (+27 more)

### Community 28 - "ProfileError"
Cohesion: 0.12
Nodes (19): test_duplicate_json_profile_property_rejected(), test_invalid_profile_fields_rejected(), test_malformed_and_oversized_profiles_rejected(), test_profile_rejects_secret_or_executable_fields(), test_profile_store_bound_keeps_ipc_responses_small(), test_profile_store_corruption_and_exact_deletion(), test_profile_store_duplicate_requires_explicit_replace(), test_profile_store_import_list_select_remove_and_permissions() (+11 more)

### Community 29 - "run_flood_trial"
Cohesion: 0.15
Nodes (9): cleanup_topology(), legit_connect(), main(), read_server_cpu(), run_flood_trial(), setup_topology(), start_flood(), start_server() (+1 more)

### Community 30 - "AccountAPIError"
Cohesion: 0.15
Nodes (5): AccountAPIError, bind(), public_device_identity(), _unavailable(), TestPublicDeviceIdentity

### Community 31 - "get_crypto_status"
Cohesion: 0.24
Nodes (8): get_crypto_status(), collect_sanity(), ensure_results_dir(), main(), _require_native_pqc(), results_dir(), _run(), run_system()

### Community 32 - ".__init__"
Cohesion: 0.15
Nodes (8): Card, DataRow, gui_label(), MetricCard, NavRail, scroll_page(), StatusRow, SummaryBlock

### Community 33 - "test_onboarding.py"
Cohesion: 0.10
Nodes (16): ConnectionState, _make_arch_source_archive(), profile_json(), profile_value(), server_public_key(), _stable_archive_digest(), test_arch_development_archive_is_checksum_verified_and_secret_free(), test_deleting_active_profile_returns_to_setup_required() (+8 more)

### Community 36 - "test_crypto_protocol.py"
Cohesion: 0.07
Nodes (45): Direction, HandshakeError, pack_cookie_response(), unpack_cookie_response(), exchange(), exchange_mldsa(), exchange_v3(), find_client() (+37 more)

### Community 37 - "benchmarks.py"
Cohesion: 0.26
Nodes (8): collect_environment(), _cpu_model(), _git_commit(), _liboqs_version(), main(), require_native_pqc(), _results_dir_for_run(), run_full_suite()

### Community 38 - "AuthorizedClients"
Cohesion: 0.07
Nodes (21): Account storage, authentication, and device binding (Milestone 4), Administrator device approval (Milestone 4.5), Authentication API, Desktop client, `GET /auth/me`, `GET /devices` and `POST /devices`, HTTPS configuration and service, Input and password policy (+13 more)

### Community 39 - "kemtls.py"
Cohesion: 0.08
Nodes (12): main(), measure_rehandshake(), measure_rekey(), require_native_pqc(), run_benchmark(), Channel, HandshakeState, pack_cookie_challenge() (+4 more)

### Community 40 - "AccountSession"
Cohesion: 0.14
Nodes (3): AccountSession, UserProfile, TestAccountSession

### Community 41 - "ipc_recv"
Cohesion: 0.09
Nodes (7): get_peer_uid(), ipc_recv(), ipc_send(), _recv_exact(), TestIPCFraming, TestMalformedIPC, test_public_enrollment_roundtrip_over_real_ipc_frame()

### Community 42 - "IPPool"
Cohesion: 0.14
Nodes (8): A-08 — Server architecture cannot support real multi-client routing, test_session_clock_is_monotonic(), test_static_leases_are_reserved_from_dynamic_allocations(), test_ip_pool_allocation_release(), test_static_ip_duplicate_prevention(), IPPool, ServerSession, SessionManager

### Community 43 - "PQCProvider"
Cohesion: 0.12
Nodes (7): PQCProvider, _make_mldsa_identities(), _make_v2_identities(), _make_v3_identities(), identities(), mldsa_identities(), v3_identities()

### Community 44 - "fingerprint"
Cohesion: 0.09
Nodes (23): _make_v2_endpoints(), _make_v3_endpoints(), _establish_session(), KEMTLSClient, KEMTLSClientV3, KEMTLSServer, KEMTLSServerV3, TranscriptHasher (+15 more)

### Community 46 - "bearer"
Cohesion: 0.27
Nodes (11): bearer(), bind(), device_identity(), test_bind_device_records_public_identity_only(), test_device_binding_never_changes_vpn_authorization(), test_device_endpoints_require_a_valid_session(), test_device_limit_per_account(), test_device_owned_by_another_account_is_rejected() (+3 more)

### Community 47 - "Desktop Milestone 3 managed installation"
Cohesion: 0.33
Nodes (6): Arch / Omarchy, Create a public server profile on the Ubuntu administrator host, Debian / Ubuntu 26.04-class, Desktop Milestone 3 managed installation, Offline enrollment administration, Packaging foundation

### Community 48 - "VPNServer"
Cohesion: 0.16
Nodes (8): A-06 — Rekey cannot synchronize, A-07 — UDP endpoint negotiation is functionally broken, configure_tun(), open_tun(), recv_exact(), recv_message(), send_message(), VPNServer

### Community 49 - "ClientStatus"
Cohesion: 0.08
Nodes (6): ClientStatus, FakeIPC, TestAccountAwareHome, TestClientStatus, TestGUIHeadless, test_client_status_serialization_and_real_schema()

### Community 51 - "generate_tables.py"
Cohesion: 0.29
Nodes (5): generate(), generate_figures(), load_all_csv(), main(), text_table()

### Community 52 - "PacketOverheadAnalyzer"
Cohesion: 0.16
Nodes (4): LayerOverhead, PacketEfficiencyResult, PacketOverheadAnalyzer, test_packet_overhead_output()

### Community 53 - "test_account_api.py"
Cohesion: 0.16
Nodes (22): login(), raw_connection(), register(), test_chunked_oversized_body_is_rejected_without_content_length(), test_concurrent_sessions_and_revoke_all_store_operation(), test_default_session_lifetime_is_twelve_hours(), test_disabled_user_has_same_failure_and_old_session_stops(), test_duplicate_username_and_email_are_specific_registration_conflicts() (+14 more)

### Community 55 - "test_deployment.py"
Cohesion: 0.10
Nodes (15): db(), firewall_commands(), staged_privileged_tree(), test_bad_server_config_fails_before_tun(), test_client_options_validate(), test_client_private_permissions(), test_database_rejects_malformed_and_conflicting(), test_dns_fail_safe_and_restore() (+7 more)

### Community 57 - "PQ-VPN Evaluation — Validity Report"
Cohesion: 0.18
Nodes (10): 1. How the results were located, 2. Per-check findings (Step 1 checklist), 3. Additional harness findings (beyond the checklist), 4. Cell-by-cell status matrix, 5. What this means for the paper, Data-plane throughput / latency (M2), Handshake cost — bytes, Handshake cost — time (M1 connect) & CPU (+2 more)

### Community 58 - "AccountStore"
Cohesion: 0.14
Nodes (12): test_session_store_validates_inputs_and_expiry(), test_corrupt_database_fails_with_domain_error(), test_current_version_with_incompatible_layout_fails(), test_database_does_not_repermission_an_unsafe_shared_directory(), test_database_path_rejects_database_symlink(), test_database_path_rejects_symlink_component(), test_unversioned_nonempty_database_is_not_silently_migrated(), test_version_1_with_incompatible_layout_is_not_migrated() (+4 more)

### Community 59 - "UserRecord"
Cohesion: 0.23
Nodes (6): AuthenticatedContext, normalize_email(), normalize_username(), UserRecord, _utc_now(), _validate_enabled()

### Community 60 - "Security Audit — 2026-09-05"
Cohesion: 0.09
Nodes (21): 2026-09-05 focused follow-up findings, A-02 — Clients are not authenticated or authorized, A-03 — Legacy/ambiguous PQC selection and unsafe wire choices, A-04 — Non-directional key schedule, A-05 — AES-GCM nonce construction and replay handling are unsafe, A-09 — No real host/client routing lifecycle, A-10 — Production silently falls back to an emulated TUN, A-11 — MTU accounting is incorrect and unapplied (+13 more)

### Community 62 - "provision_eval_host.sh"
Cohesion: 0.33
Nodes (10): cfg_state(), fail(), ok(), PATH, probe_netem(), probe_wireguard(), section(), provision_eval_host.sh script (+2 more)

### Community 63 - "AccountClient"
Cohesion: 0.17
Nodes (4): AccountClient, TestAccountClientConstruction, TestAccountClientLiveAPI, TestAccountClientMalformedResponses

### Community 64 - "ThroughputBenchmark"
Cohesion: 0.22
Nodes (3): PayloadResult, ThroughputBenchmark, test_throughput_benchmark_frame_size()

### Community 67 - "network.py"
Cohesion: 0.16
Nodes (19): test_firewall_order_and_scope(), test_obsolete_udp_setting_rejected(), test_config_paths_resolve_from_toml_not_cwd(), test_omitted_identity_paths_resolve_beside_toml(), test_toml_policy_defaults_and_explicit_values(), resolve(), test_setup_uses_nondefault_toml(), addresses() (+11 more)

### Community 68 - "test_networking.py"
Cohesion: 0.07
Nodes (29): kernel(), ip(), process(), NativeTun, open_pipe(), test_actual_client_cleanup_removes_guard(), test_closed_tun_errors(), test_doctor_ipv6_is_read_only() (+21 more)

### Community 69 - "accounts.py"
Cohesion: 0.09
Nodes (17): test_invalid_email_rejected(), test_invalid_username_rejected(), test_newer_schema_version_fails_closed(), test_password_hash_helpers_fail_safely_and_detect_rehash(), test_password_hash_is_argon2id_and_plaintext_is_never_stored(), test_password_length_boundaries_and_no_secret_in_errors(), test_version_1_database_migrates_with_devices_pending(), AccountAlreadyExists (+9 more)

### Community 71 - "._connection"
Cohesion: 0.34
Nodes (3): DeviceRecord, _validate_device_status(), _validate_id()

### Community 72 - "app"
Cohesion: 0.50
Nodes (3): app(), client(), config()

### Community 74 - "identity.py"
Cohesion: 0.08
Nodes (31): test_authorize_request_preserves_assigned_ip_validation(), test_enrollment_cli_generation_and_server_authorization(), test_enrollment_roundtrip_is_public_only(), test_enrollment_size_duplicate_key_and_output_symlink_rejected(), test_identity_rejects_mismatch_partial_and_symlink(), test_identity_repairs_public_without_rotating_private(), test_malformed_enrollment_fields_rejected(), main() (+23 more)

### Community 75 - "results-summary/README.md"
Cohesion: 0.22
Nodes (5): Contents, Harness changes made in this pass (eval files only), PQ-VPN Evaluation — Results Summary, Status at a glance, Why cells are PENDING

### Community 76 - "Auto-routing rules"
Cohesion: 0.12
Nodes (15): Always-on rules, API design (API, endpoint, interface, protocol, message format), Asking about the codebase (how does X work, where is Y, what calls Z, explain the architecture), Auto-routing rules, Bug fix (fix, broken, error, crash, failing test, doesn't work, regression), Code review (review, check this, look at, PR, before merge, is this correct), Debugging (debug, trace, why does, unexpected, investigate), Documentation (document, explain, ADR, decision record) (+7 more)

### Community 77 - "PQVPN Design"
Cohesion: 0.13
Nodes (15): Authentication boundary, Benchmarking and measurement harness, Cryptographic and Protocol Design, D1: Client authentication flow for v3, Deployment and diagnostics, Deployment boundaries, Design decisions, Handshake (+7 more)

### Community 78 - "PQ-VPN"
Cohesion: 0.11
Nodes (18): Architecture, Client enrollment, Cryptography, Current status, Desktop client, Docker, Documentation, Features (+10 more)

### Community 80 - "_device_setup"
Cohesion: 0.14
Nodes (5): _device_setup(), IdentityIPC, live_account_api(), _pyside6_available(), qapp()

### Community 81 - "datetime"
Cohesion: 0.29
Nodes (4): _parse_timestamp(), SessionRecord, _utc_timestamp(), _validate_token_hash()

### Community 84 - "Remaining Steps for the Paper / Artifact"
Cohesion: 0.22
Nodes (9): 1. Run the campaign on a capable host and commit the numbers — **blocking**, 2. Implement + run the data-plane throughput/latency benchmark (M2) — **blocking for the trade-off claim**, 3. Create the `v3-paper-artifact` tag — **not yet done**, 4. Record the ARTIFACT.md "recorded-run" table, 5. Mint the Zenodo DOI, 6. Optional: live VPS check, 7. Write the paper draft, Recommended order (summary) (+1 more)

### Community 85 - "measure_throughput.py"
Cohesion: 0.13
Nodes (18): cleanup(), connect_client(), main(), read_vmrss_kb(), run_measurement(), setup_topology(), start_server(), wait_for_tunnel() (+10 more)

### Community 86 - "Reproducibility Artifact"
Cohesion: 0.08
Nodes (25): Assumptions, Baseline VPN comparison (optional), Evaluation results, Expected output, Expected outputs, Expected runtime, Expected wire sizes (deterministic), Formal verification (+17 more)

### Community 87 - "fail"
Cohesion: 0.24
Nodes (10): IPv6 policy, IPv6 leakage and revocation boundaries, Unsupported IPv6 and revocation, Changes and boundaries, Current validation matrix, Pre-VPS hardening — 2026-09-07, Source-review continuation, network() (+2 more)

### Community 88 - "BoundedRateLimiter"
Cohesion: 0.27
Nodes (3): test_limiter_is_monotonic_bounded_and_removes_stale_entries(), BoundedRateLimiter, _RateEntry

### Community 90 - "2. Results tables"
Cohesion: 0.25
Nodes (8): 2. Results tables, Table A — Connect time M1 (ms), median [95% CI], n = 30, Table B — Handshake CPU M2 (ms), n = 50, Table C — Handshake wire bytes M3 — **final** (see §1.2), Table D — Data-plane throughput M5, iperf3 TCP -t 20, Table E — Rekey & re-handshake cost M6, Table F — Cookie-flood behaviour M7, Table G — Memory per session M8

### Community 92 - "PQ-VPN Evaluation Write-Up"
Cohesion: 0.29
Nodes (7): 0. The claim this evaluation defends, 3. Interpretation, 4. Threats to validity, 5. Reproducibility pointer, 6. Figures, 7. Measurement scripts, PQ-VPN Evaluation Write-Up

### Community 94 - "namespace_vpn.sh"
Cohesion: 0.57
Nodes (6): cleanup(), filter_meaningful_ipv6_routes(), namespace_vpn.sh script, snapshot_meaningful_ipv6_routes(), start_client(), wait_bounded()

### Community 96 - "1. Headline findings"
Cohesion: 0.29
Nodes (7): 1.1 Security position — **supported, final**, 1.2 Handshake cost — **supported**, 1.3 Data-plane throughput / latency — **measured, framed as context**, 1.4 Key rotation — **hitless**, 1.5 DoS resilience — **cookie mechanism validated**, 1.6 Memory per session — **modest for a userspace VPN**, 1. Headline findings

### Community 97 - "Re-run Commands — producing the PENDING cells on a capable host"
Cohesion: 0.29
Nodes (7): 1. Host capability gate (run first), 2. One command for the whole campaign, 3. Per-cell commands (if you want to run cells individually), 4. Validate the two new baselines before trusting them, 5. Still outstanding: networked data-plane throughput (M2), 6. Publish the results so they survive, Re-run Commands — producing the PENDING cells on a capable host

### Community 98 - "Quick start"
Cohesion: 0.33
Nodes (6): 1. Install native liboqs, 2. Set up the Python environment, 3. Generate identities, 4. Configure and run, Prerequisites, Quick start

### Community 100 - "/dev — Toolchain Status & Override"
Cohesion: 0.40
Nodes (4): /dev — Toolchain Status & Override, Notes, When invoked with args, When invoked with no args

### Community 101 - "Encrypted frame"
Cohesion: 0.33
Nodes (6): Authentication boundary, Encrypted frame, Hybrid re-handshake (post-compromise security), Protocol v3, Protocol v3-mldsa (comparison suite), Stateless cookie (DoS resistance)

### Community 102 - "SourceRateLimiter"
Cohesion: 0.33
Nodes (5): A-17 — Resource exhaustion controls are insufficient, test_rate_limiter_caps_unique_sources(), test_rate_limiter_prunes_sources(), test_source_rate_limiter_window(), SourceRateLimiter

### Community 103 - "verify_formal.sh"
Cohesion: 0.50
Nodes (4): check_results(), HS_LEMMAS, PCS_LEMMAS, verify_formal.sh script

### Community 104 - "test_native_authenticated_session_records"
Cohesion: 0.50
Nodes (3): test_mock_never_quantum_safe(), test_native_authenticated_session_records(), test_native_mlkem_self_test()

### Community 112 - "netem_profiles.sh"
Cohesion: 0.14
Nodes (18): eval_provenance_fields(), netem_apply(), netem_delay_each(), netem_loss(), netem_mtu(), netem_profile_valid(), netem_require_tools(), netem_profiles.sh script (+10 more)

## Knowledge Gaps
- **181 isolated node(s):** `netem_profiles.sh script`, `run_pqvpn_net.sh script`, `HandshakeState`, `pqvpn`, `reproduce.sh script` (+176 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 700 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **36 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VPNClient` connect `test_runtime.py` to `test_crypto_protocol.py`, `AuthorizedClients`, `kemtls.py`, `identity.py`, `HybridKEM`, `client.py`, `fingerprint`, `VPNServer`, `test_udp_bind_failure_cleans_every_resource`, `_pack_header`, `NetworkQualityMonitor`, `ClientService`, `Security Audit — 2026-09-05`?**
  _High betweenness centrality (0.051) - this node is a cross-community bridge._
- **Why does `fingerprint()` connect `fingerprint` to `test_onboarding.py`, `doctor_run`, `PQSignatureProvider`, `test_crypto_protocol.py`, `benchmarks.py`, `AuthorizedClients`, `kemtls.py`, `test_networking.py`, `accounts.py`, `identity.py`, `client.py`, `run_pqvpn.py`, `_pack_header`, `HandshakeBenchmark`, `test_deployment.py`, `test_accounts.py`, `test_runtime.py`, `ProfileError`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._
- **Why does `HybridKEM` connect `HybridKEM` to `PQSignatureProvider`, `test_crypto_protocol.py`, `benchmarks.py`, `ECCProvider`, `kemtls.py`, `fingerprint`, `VPNServer`, `test_runtime.py`, `X25519PrivateKey`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Are the 39 inferred relationships involving `HandshakeError` (e.g. with `test_concurrent_duplicate_replay_exactly_one_success()` and `test_cookie_response_invalid_too_short()`) actually correct?**
  _`HandshakeError` has 39 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `MainWindow` (e.g. with `TestAccountAwareHome` and `TestAccountGUI`) actually correct?**
  _`MainWindow` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 6 inferred relationships involving `AccountStore` (e.g. with `Location and permissions` and `raw_connection()`) actually correct?**
  _`AccountStore` has 6 INFERRED edges - model-reasoned connections that need verification._
- **Are the 5 inferred relationships involving `ClientService` (e.g. with `EnrollmentRequest` and `ProfileStore`) actually correct?**
  _`ClientService` has 5 INFERRED edges - model-reasoned connections that need verification._