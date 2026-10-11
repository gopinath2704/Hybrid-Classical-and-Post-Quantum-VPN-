# Graph Report - Hybrid-Classical-and-Post-Quantum-VPN-  (2026-10-11)

## Corpus Check
- 62 files · ~143,270 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 25 file(s) not represented in the graph (top: (none) 12, .service 4, .toml 3)

## Summary
- 2151 nodes · 5033 edges · 130 communities (83 shown, 47 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 389 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `13cf28b6`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- HandshakeError
- doctor_run
- HandshakeBenchmark
- identity.py
- TestSessionKeyStore
- MainWindow
- PQCProvider
- TestKeyManager
- client.py
- PQVPN Deployment
- AccountAPIConfig
- TestHybridKEM
- test_client_app.py
- FakeSocket
- run_pqvpn.py
- reproduce.sh
- generate_tables.py
- SessionKeyStore
- kemtls.py
- generate_server_identity
- hybrid_crypto.py
- NetworkQualityMonitor
- ClientService
- test_accounts.py
- create_app
- test_runtime.py
- CookieProtector
- ProfileError
- flood_clienthello.py
- public_device_identity
- cli.py
- .__init__
- test_onboarding.py
- IPCClient
- AccountAPIError
- test_crypto_protocol.py
- benchmarks.py
- AuthorizedClients
- _MockInsecurePQCProvider
- AccountSession
- ipc_recv
- ClientHello
- fingerprint
- HybridKEM
- ._render
- bearer
- KeyManager
- PongFilter
- ClientStatus
- Path
- runtime.py
- get_crypto_status
- test_account_api.py
- MTUMonitor
- test_deployment.py
- pqvpn
- PQ-VPN Evaluation — Validity Report
- AccountStore
- ._connection
- Security Audit — 2026-09-05
- TestAccountGUI
- provision_eval_host.sh
- AccountClient
- ThroughputBenchmark
- _IPCWorker
- PowerButton
- test_networking.py
- ClientNetwork
- ECCProvider
- measure_throughput.py
- InvalidAccountInput
- app
- main
- results-summary/README.md
- Auto-routing rules
- PQVPN Design
- PQ-VPN
- TestECCProvider
- _device_setup
- accounts.py
- SessionManager
- test_udp_bind_failure_cleans_every_resource
- Remaining Steps for the Paper / Artifact
- IPv6Guard
- Reproducibility Artifact
- fail
- BoundedRateLimiter
- 2. Results tables
- Formal verification
- PQ-VPN Evaluation Write-Up
- namespace_vpn.sh
- run_pqvpn_net.sh
- 1. Headline findings
- Re-run Commands — producing the PENDING cells on a capable host
- measure_memory.py
- /dev — Toolchain Status & Override
- Encrypted frame
- TestClientService
- verify_formal.sh
- TestPQCProvider
- Tun
- bench_netem.sh
- _secure_zero
- FakeIPC
- TestAccountAwareHome
- TUNInterface
- netem_profiles.sh
- install-liboqs.sh
- server-network.sh
- HybridKeyBundle
- run_resumption_net.sh
- _socket_path
- SessionRecord
- test_managed_authentication_close_has_clear_non_claiming_message
- ServerProfile
- IPPool
- ServerConfig
- Desktop Milestone 3 managed installation
- VPNClient
- SourceRateLimiter
- test_real_namespace_tunnel
- BodyLimitMiddleware

## God Nodes (most connected - your core abstractions)
1. `HandshakeError` - 93 edges
2. `MainWindow` - 79 edges
3. `fingerprint()` - 64 edges
4. `AccountStore` - 60 edges
5. `ClientService` - 53 edges
6. `VPNClient` - 50 edges
7. `HybridKEM` - 49 edges
8. `ClientStatus` - 45 edges
9. `AccountClient` - 45 edges
10. `AuthorizedClients` - 42 edges

## Surprising Connections (you probably didn't know these)
- `1-RTT session resumption` --references--> `ResumptionTicketKey`  [INFERRED]
  docs/design.md → handshake/kemtls.py
- ``.pqenroll` schema` --references--> `AuthorizedClients`  [INFERRED]
  docs/design.md → vpn/identity.py
- `2026-09-05 focused follow-up findings` --references--> `ClientNetwork`  [INFERRED]
  docs/security_audit.md → vpn/runtime.py
- `Packaging foundation` --references--> `PQCUnavailableError`  [INFERRED]
  docs/deployment.md → crypto/hybrid_crypto.py
- `A-03 — Legacy/ambiguous PQC selection and unsafe wire choices` --references--> `PQCProvider`  [INFERRED]
  docs/security_audit.md → crypto/hybrid_crypto.py

## Import Cycles
- None detected.

## Communities (130 total, 47 thin omitted)

### Community 0 - "HandshakeError"
Cohesion: 0.07
Nodes (14): _compute_finished_mac(), derive_schedule_mldsa(), derive_schedule_resume(), derive_schedule_v3(), _derive_secrets(), _expand(), HandshakeError, HandshakeSession (+6 more)

### Community 1 - "doctor_run"
Cohesion: 0.13
Nodes (17): test_doctor_production_scope(), test_doctor_reports_privileged_code_failure(), command(), doctor_run(), available(), check(), database(), forwarding() (+9 more)

### Community 2 - "HandshakeBenchmark"
Cohesion: 0.12
Nodes (6): HandshakeBenchmark, HandshakeMetric, SuiteSummary, _write_suite_csv(), test_handshake_benchmark_output(), test_benchmarks_cpu_split()

### Community 3 - "identity.py"
Cohesion: 0.12
Nodes (16): test_client_private_permissions(), test_first_identity_ensure_is_idempotent_and_private(), test_identity_rejects_mismatch_partial_and_symlink(), test_identity_repairs_public_without_rotating_private(), _atomic_new(), client_public_identity(), ensure_client_identity(), load_client_private() (+8 more)

### Community 6 - "PQCProvider"
Cohesion: 0.09
Nodes (10): PQCProvider, PQSignatureProvider, A-03 — Legacy/ambiguous PQC selection and unsafe wire choices, _make_mldsa_identities(), _make_v2_identities(), _make_v3_identities(), identities(), mldsa_identities() (+2 more)

### Community 8 - "client.py"
Cohesion: 0.13
Nodes (5): _launch_gui(), main(), NavButton, NavRail, SummaryBlock

### Community 9 - "PQVPN Deployment"
Cohesion: 0.07
Nodes (28): Completed validation record — 2026-09-15, Current validation record, Current validation record, Disposable root namespace gate, DNS policy, Exact tested dependencies, Firewall policy and subnet selection, Install and provision, then diagnose (+20 more)

### Community 10 - "AccountAPIConfig"
Cohesion: 0.16
Nodes (13): test_dedicated_config_loads_relative_paths_and_rejects_unknown_values(), test_login_rate_limit_is_source_scoped(), test_registration_limiter_is_separate_from_login_limiter(), test_registration_never_changes_vpn_authorization(), test_remote_or_implicit_cleartext_bind_fails_closed(), test_tls_files_are_required_regular_and_private_key_is_private(), live_account_api(), AccountAPIConfig (+5 more)

### Community 13 - "test_client_app.py"
Cohesion: 0.12
Nodes (9): account_ux_state(), _sanitized_message(), SessionState, _pyside6_available(), qapp(), test_error_sanitization_is_bounded_and_redacts_secrets(), TestAccountErrorMessages, TestAccountUXState (+1 more)

### Community 14 - "FakeSocket"
Cohesion: 0.14
Nodes (4): FakeSocket, FakeTun, test_graceful_server_stop_has_no_exception(), make_socket()

### Community 15 - "run_pqvpn.py"
Cohesion: 0.09
Nodes (19): bootstrap_ci(), evaluate_suite(), _liboqs_version(), main(), measure_encrypt_throughput(), measure_handshakes_per_sec(), measure_memory_per_session(), require_native_pqc() (+11 more)

### Community 17 - "generate_tables.py"
Cohesion: 0.21
Nodes (8): generate(), generate_figures(), generate_summary(), group_data(), load_all_csv(), main(), text_table(), test_generate_tables_roundtrip()

### Community 19 - "kemtls.py"
Cohesion: 0.07
Nodes (17): A-13 — Handshake parsers accept inconsistent/trailing data, ClientHelloMLDSA, ClientHelloV3, ClientKeyExchangeMLDSA, ClientKeyExchangeV3, _fields(), _fixed(), HandshakeState (+9 more)

### Community 20 - "generate_server_identity"
Cohesion: 0.22
Nodes (10): connected(), test_cookie_always_mode_handshake_completes(), test_cookie_off_mode_no_challenge(), test_server_session_timeout_disconnects_client(), test_v3_resumption_resumes_end_to_end_not_fallback(), make_client(), _atomic_private(), generate_client_identity() (+2 more)

### Community 22 - "NetworkQualityMonitor"
Cohesion: 0.11
Nodes (4): test_quality_metrics_jitter_loss_reset(), test_quality_rolling_window(), NetworkQualityMonitor, QualitySnapshot

### Community 24 - "test_accounts.py"
Cohesion: 0.08
Nodes (34): _cli(), public_identity(), raw_connection(), review(), store(), test_add_and_list_multiple_devices(), test_admin_approval_is_the_only_path_into_authorized_clients(), test_admin_lists_pending_devices() (+26 more)

### Community 25 - "create_app"
Cohesion: 0.17
Nodes (19): AuthenticatedContext, create_app(), bind_device(), database_error(), internal_error(), list_devices(), login(), logout() (+11 more)

### Community 26 - "test_runtime.py"
Cohesion: 0.15
Nodes (19): ipv4(), test_authenticated_keepalive_prevents_idle_expiry(), test_control_activity_is_counted_after_validation(), test_control_loss_restores_resources(), test_delayed_rekey_keeps_data_forwarding(), test_from_frame_routes_all_protocol_versions(), test_genuinely_idle_session_expires_and_cleans_up(), test_inner_source_validation() (+11 more)

### Community 27 - "CookieProtector"
Cohesion: 0.15
Nodes (9): CookieProtector, test_cookie_accepted_just_before_and_after_rotation(), test_cookie_bad_length_rejected(), test_cookie_no_crash_at_boot_time(), test_cookie_protector_rotation(), test_cookie_protector_round_trip(), test_cookie_rejected_after_two_rotations(), test_cookie_wrong_ip_rejected() (+1 more)

### Community 28 - "ProfileError"
Cohesion: 0.16
Nodes (7): _atomic_write(), _decode_json(), _profile_unique_object(), ProfileError, ProfileStore, _safe_parent(), _validate_host()

### Community 29 - "flood_clienthello.py"
Cohesion: 0.15
Nodes (10): cleanup_topology(), craft_clienthello(), legit_connect(), main(), read_server_cpu(), run_flood_trial(), setup_topology(), start_flood() (+2 more)

### Community 30 - "public_device_identity"
Cohesion: 0.33
Nodes (3): bind(), public_device_identity(), TestPublicDeviceIdentity

### Community 31 - "cli.py"
Cohesion: 0.08
Nodes (3): DeviceBindRequest, LoginRequest, RegisterRequest

### Community 32 - ".__init__"
Cohesion: 0.19
Nodes (6): Card, DataRow, gui_label(), MetricCard, scroll_page(), StatusRow

### Community 33 - "test_onboarding.py"
Cohesion: 0.10
Nodes (21): ConnectionState, _make_arch_source_archive(), profile_json(), profile_value(), server_public_key(), _stable_archive_digest(), test_arch_development_archive_is_checksum_verified_and_secret_free(), test_deleting_active_profile_returns_to_setup_required() (+13 more)

### Community 35 - "AccountAPIError"
Cohesion: 0.14
Nodes (3): AccountAPIError, _invalid_response(), _unavailable()

### Community 36 - "test_crypto_protocol.py"
Cohesion: 0.06
Nodes (49): Channel, Direction, FrameType, ResumptionTicketKey, exchange(), exchange_mldsa(), exchange_v3(), find_client() (+41 more)

### Community 37 - "benchmarks.py"
Cohesion: 0.09
Nodes (15): collect_environment(), _cpu_model(), _git_commit(), LayerOverhead, _liboqs_version(), main(), PacketEfficiencyResult, PacketOverheadAnalyzer (+7 more)

### Community 38 - "AuthorizedClients"
Cohesion: 0.10
Nodes (17): Account storage, authentication, and device binding (Milestone 4), Administrator device approval (Milestone 4.5), Authentication API, Desktop client, `GET /auth/me`, `GET /devices` and `POST /devices`, HTTPS configuration and service, Input and password policy (+9 more)

### Community 39 - "_MockInsecurePQCProvider"
Cohesion: 0.11
Nodes (3): _MockInsecurePQCProvider, _MockInsecureSigProvider, PQCUnavailableError

### Community 40 - "AccountSession"
Cohesion: 0.14
Nodes (3): AccountSession, UserProfile, TestAccountSession

### Community 41 - "ipc_recv"
Cohesion: 0.11
Nodes (6): get_peer_uid(), ipc_recv(), ipc_send(), _recv_exact(), TestIPCFraming, test_public_enrollment_roundtrip_over_real_ipc_frame()

### Community 42 - "ClientHello"
Cohesion: 0.16
Nodes (11): A-01 — Server is not authenticated, ClientHello, ClientKeyExchange, derive_schedule(), ServerFinished, ServerHello, test_frozen_v2_handshake_serialization(), test_message_fixed_sizes() (+3 more)

### Community 43 - "fingerprint"
Cohesion: 0.12
Nodes (20): _make_mldsa_endpoints(), _make_v2_endpoints(), KEMTLSClient, KEMTLSClientMLDSA, KEMTLSServer, KEMTLSServerMLDSA, ServerHelloMLDSA, test_exact_reduced_handshake_sizes() (+12 more)

### Community 44 - "HybridKEM"
Cohesion: 0.08
Nodes (14): HybridKEM, _make_v3_endpoints(), KEMTLSClientV3, KEMTLSServerV3, ResumptionClientHandshake, ResumptionServerHandshake, TranscriptHasher, test_transcript_hash_copy_and_count() (+6 more)

### Community 46 - "bearer"
Cohesion: 0.27
Nodes (11): bearer(), bind(), device_identity(), test_bind_device_records_public_identity_only(), test_device_binding_never_changes_vpn_authorization(), test_device_endpoints_require_a_valid_session(), test_device_limit_per_account(), test_device_owned_by_another_account_is_rejected() (+3 more)

### Community 48 - "PongFilter"
Cohesion: 0.14
Nodes (7): test_actual_client_cleanup_removes_guard(), network(), test_doctor_ipv6_is_read_only(), test_exact_mtu_calculation(), test_native_installer_verifies_commit_before_build(), test_read_only_connectivity_detection(), PongFilter

### Community 49 - "ClientStatus"
Cohesion: 0.12
Nodes (4): ClientStatus, TestClientStatus, TestGUIHeadless, test_client_status_serialization_and_real_schema()

### Community 51 - "runtime.py"
Cohesion: 0.07
Nodes (25): A-07 — UDP endpoint negotiation is functionally broken, _establish_session(), main(), measure_rehandshake(), measure_rekey(), require_native_pqc(), run_benchmark(), pack_cookie_challenge() (+17 more)

### Community 52 - "get_crypto_status"
Cohesion: 0.24
Nodes (8): get_crypto_status(), collect_sanity(), ensure_results_dir(), main(), _require_native_pqc(), results_dir(), _run(), run_system()

### Community 53 - "test_account_api.py"
Cohesion: 0.15
Nodes (24): login(), raw_connection(), register(), test_chunked_oversized_body_is_rejected_without_content_length(), test_concurrent_sessions_and_revoke_all_store_operation(), test_default_session_lifetime_is_twelve_hours(), test_disabled_user_has_same_failure_and_old_session_stops(), test_duplicate_username_and_email_are_specific_registration_conflicts() (+16 more)

### Community 55 - "test_deployment.py"
Cohesion: 0.07
Nodes (24): db(), firewall_commands(), staged_privileged_tree(), test_bad_server_config_fails_before_tun(), test_concurrent_database_updates_are_not_lost(), test_database_rejects_malformed_and_conflicting(), test_dns_fail_safe_and_restore(), test_doctor_is_read_only_and_reports_failures() (+16 more)

### Community 57 - "PQ-VPN Evaluation — Validity Report"
Cohesion: 0.18
Nodes (10): 1. How the results were located, 2. Per-check findings (Step 1 checklist), 3. Additional harness findings (beyond the checklist), 4. Cell-by-cell status matrix, 5. What this means for the paper, Data-plane throughput / latency (M2), Handshake cost — bytes, Handshake cost — time (M1 connect) & CPU (+2 more)

### Community 58 - "AccountStore"
Cohesion: 0.13
Nodes (13): test_session_store_validates_inputs_and_expiry(), test_session_store_validation_touch_interval_and_revocation(), test_corrupt_database_fails_with_domain_error(), test_current_version_with_incompatible_layout_fails(), test_database_does_not_repermission_an_unsafe_shared_directory(), test_database_path_rejects_database_symlink(), test_database_path_rejects_symlink_component(), test_unversioned_nonempty_database_is_not_silently_migrated() (+5 more)

### Community 59 - "._connection"
Cohesion: 0.30
Nodes (3): normalize_email(), normalize_username(), UserRecord

### Community 60 - "Security Audit — 2026-09-05"
Cohesion: 0.09
Nodes (21): 2026-09-05 focused follow-up findings, A-02 — Clients are not authenticated or authorized, A-04 — Non-directional key schedule, A-05 — AES-GCM nonce construction and replay handling are unsafe, A-06 — Rekey cannot synchronize, A-09 — No real host/client routing lifecycle, A-10 — Production silently falls back to an emulated TUN, A-11 — MTU accounting is incorrect and unapplied (+13 more)

### Community 62 - "provision_eval_host.sh"
Cohesion: 0.33
Nodes (10): cfg_state(), fail(), ok(), PATH, probe_netem(), probe_wireguard(), section(), provision_eval_host.sh script (+2 more)

### Community 63 - "AccountClient"
Cohesion: 0.14
Nodes (4): AccountClient, TestAccountClientConstruction, TestAccountClientLiveAPI, TestAccountClientMalformedResponses

### Community 64 - "ThroughputBenchmark"
Cohesion: 0.22
Nodes (3): PayloadResult, ThroughputBenchmark, test_throughput_benchmark_frame_size()

### Community 67 - "test_networking.py"
Cohesion: 0.17
Nodes (12): test_obsolete_udp_setting_rejected(), open_pipe(), test_config_paths_resolve_from_toml_not_cwd(), test_namespace_route_snapshot_ignores_only_async_kernel_link_local_routes(), test_omitted_identity_paths_resolve_beside_toml(), test_revoke_cli_explains_active_session_boundary(), test_toml_policy_defaults_and_explicit_values(), test_tun_lifecycle_and_roundtrip() (+4 more)

### Community 68 - "ClientNetwork"
Cohesion: 0.24
Nodes (9): NativeTun, test_fail_policy_with_no_ipv6_does_not_install_guard(), test_failed_atomic_block_does_not_touch_routes_or_unrelated_tables(), test_full_tunnel_blocks_ipv6_including_existing_flows_and_forwarding(), test_guard_removed_even_if_dns_undo_raises(), test_policy_defaults_and_explicit_split_block(), ClientNetwork, RouteUndo (+1 more)

### Community 70 - "measure_throughput.py"
Cohesion: 0.26
Nodes (10): cleanup(), connect_client(), main(), measure_iperf3_tcp(), measure_iperf3_udp(), measure_ping(), run_profile(), setup_topology() (+2 more)

### Community 71 - "InvalidAccountInput"
Cohesion: 0.19
Nodes (9): AccountNotFound, DeviceRecord, InvalidAccountInput, _utc_now(), _validate_device_name(), _validate_device_status(), _validate_enabled(), _validate_id() (+1 more)

### Community 72 - "app"
Cohesion: 0.50
Nodes (3): app(), client(), config()

### Community 74 - "main"
Cohesion: 0.19
Nodes (15): test_authorize_request_preserves_assigned_ip_validation(), test_enrollment_cli_generation_and_server_authorization(), test_enrollment_roundtrip_is_public_only(), test_enrollment_size_duplicate_key_and_output_symlink_rejected(), test_malformed_enrollment_fields_rejected(), test_managed_service_export_is_public_and_identity_is_stable(), main(), _parser() (+7 more)

### Community 75 - "results-summary/README.md"
Cohesion: 0.22
Nodes (5): Contents, Harness changes made in this pass (eval files only), PQ-VPN Evaluation — Results Summary, Status at a glance, Why cells are PENDING

### Community 76 - "Auto-routing rules"
Cohesion: 0.12
Nodes (15): Always-on rules, API design (API, endpoint, interface, protocol, message format), Asking about the codebase (how does X work, where is Y, what calls Z, explain the architecture), Auto-routing rules, Bug fix (fix, broken, error, crash, failing test, doesn't work, regression), Code review (review, check this, look at, PR, before merge, is this correct), Debugging (debug, trace, why does, unexpected, investigate), Documentation (document, explain, ADR, decision record) (+7 more)

### Community 77 - "PQVPN Design"
Cohesion: 0.14
Nodes (14): Benchmarking and measurement harness, Cryptographic and Protocol Design, D1: Client authentication flow for v3, D6: Data-plane implementation scope, Deployment and diagnostics, Deployment boundaries, Design decisions, Handshake (+6 more)

### Community 78 - "PQ-VPN"
Cohesion: 0.08
Nodes (24): 1. Install native liboqs, 2. Set up the Python environment, 3. Generate identities, 4. Configure and run, Architecture, Client enrollment, Cryptography, Current status (+16 more)

### Community 81 - "accounts.py"
Cohesion: 0.16
Nodes (7): AccountAlreadyExists, AccountError, _parse_timestamp(), PasswordHashError, SessionRecord, _utc_timestamp(), _validate_token_hash()

### Community 84 - "Remaining Steps for the Paper / Artifact"
Cohesion: 0.22
Nodes (9): 1. Run the campaign on a capable host and commit the numbers — **blocking**, 2. Run the data-plane throughput/latency benchmark (M2) on a capable host — **blocking for the trade-off claim**, 3. Create the `v3-paper-artifact` tag — **not yet done**, 4. Record the ARTIFACT.md "recorded-run" table, 5. Mint the Zenodo DOI, 6. Optional: live VPS check, 7. Write the paper draft, Recommended order (summary) (+1 more)

### Community 86 - "Reproducibility Artifact"
Cohesion: 0.12
Nodes (17): Additional evaluation scripts, Baseline VPN comparison (optional), Evaluation results, Expected outputs, Expected runtime, Expected wire sizes (deterministic), Hardware requirements, One-command setup (+9 more)

### Community 87 - "fail"
Cohesion: 0.27
Nodes (9): IPv6 policy, IPv6 leakage and revocation boundaries, Unsupported IPv6 and revocation, Changes and boundaries, Current validation matrix, Pre-VPS hardening — 2026-09-07, Source-review continuation, fail() (+1 more)

### Community 88 - "BoundedRateLimiter"
Cohesion: 0.27
Nodes (3): test_limiter_is_monotonic_bounded_and_removes_stale_entries(), BoundedRateLimiter, _RateEntry

### Community 90 - "2. Results tables"
Cohesion: 0.25
Nodes (8): 2. Results tables, Table A — Connect time M1 (ms), median [95% CI], n = 30, Table B — Handshake CPU M2 (ms), n = 50, Table C — Handshake wire bytes M3 — **final** (see §1.2), Table D — Data-plane throughput M5, iperf3 TCP -t 20, Table E — Rekey & re-handshake cost M6, Table F — Cookie-flood behaviour M7, Table G — Memory per session M8

### Community 91 - "Formal verification"
Cohesion: 0.22
Nodes (9): Assumptions, Expected output, Formal verification, Hybrid security argument, Model structure, Prerequisites, Recorded run, Running (+1 more)

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
Nodes (7): 1. Host capability gate (run first), 2. One command for the whole campaign, 3. Per-cell commands (if you want to run cells individually), 4. Validate the two new baselines before trusting them, 5. Networked data-plane throughput (M2), 6. Publish the results so they survive, Re-run Commands — producing the PENDING cells on a capable host

### Community 98 - "measure_memory.py"
Cohesion: 0.27
Nodes (8): cleanup(), connect_client(), main(), read_vmrss_kb(), run_measurement(), setup_topology(), start_server(), wait_for_tunnel()

### Community 100 - "/dev — Toolchain Status & Override"
Cohesion: 0.40
Nodes (4): /dev — Toolchain Status & Override, Notes, When invoked with args, When invoked with no args

### Community 101 - "Encrypted frame"
Cohesion: 0.29
Nodes (7): 1-RTT session resumption, Authentication boundary, Encrypted frame, Hybrid re-handshake (post-compromise security), Protocol v3, Protocol v3-mldsa (comparison suite), Stateless cookie (DoS resistance)

### Community 103 - "verify_formal.sh"
Cohesion: 0.50
Nodes (4): check_results(), HS_LEMMAS, PCS_LEMMAS, verify_formal.sh script

### Community 105 - "Tun"
Cohesion: 0.18
Nodes (7): kernel(), ip(), process(), test_exact_previous_route_restoration(), test_partial_dns_failure_always_reverts(), test_route_apply_failure_rolls_back(), Tun

### Community 111 - "TUNInterface"
Cohesion: 0.16
Nodes (5): test_closed_tun_errors(), test_native_tun_opens_nonblocking(), test_tun_defaults_and_metadata(), TUNInterface, TUNMode

### Community 112 - "netem_profiles.sh"
Cohesion: 0.14
Nodes (18): eval_provenance_fields(), netem_apply(), netem_delay_each(), netem_loss(), netem_mtu(), netem_profile_valid(), netem_require_tools(), netem_profiles.sh script (+10 more)

### Community 122 - "ServerProfile"
Cohesion: 0.23
Nodes (5): test_invalid_profile_fields_rejected(), test_profile_rejects_secret_or_executable_fields(), test_profile_store_bound_keeps_ipc_responses_small(), test_profile_store_duplicate_requires_explicit_replace(), ServerProfile

### Community 123 - "IPPool"
Cohesion: 0.25
Nodes (4): test_static_leases_are_reserved_from_dynamic_allocations(), test_ip_pool_allocation_release(), test_static_ip_duplicate_prevention(), IPPool

### Community 124 - "ServerConfig"
Cohesion: 0.43
Nodes (7): test_firewall_order_and_scope(), test_configuration_defaults_are_safe(), interface_name(), ServerConfig, validate_server(), main(), render()

### Community 125 - "Desktop Milestone 3 managed installation"
Cohesion: 0.33
Nodes (6): Arch / Omarchy, Create a public server profile on the Ubuntu administrator host, Debian / Ubuntu 26.04-class, Desktop Milestone 3 managed installation, Offline enrollment administration, Packaging foundation

### Community 126 - "VPNClient"
Cohesion: 0.10
Nodes (18): IPC boundary, Managed desktop onboarding, `.pqenroll` schema, `.pqvpn` schema, test_client_options_validate(), test_fail_policy_rejects_before_tun_or_routing(), test_unknown_policy_rejected(), test_automatic_rekey_short_interval() (+10 more)

### Community 127 - "SourceRateLimiter"
Cohesion: 0.33
Nodes (5): A-17 — Resource exhaustion controls are insufficient, test_rate_limiter_caps_unique_sources(), test_rate_limiter_prunes_sources(), test_source_rate_limiter_window(), SourceRateLimiter

## Knowledge Gaps
- **180 isolated node(s):** `netem_profiles.sh script`, `run_pqvpn_net.sh script`, `HandshakeState`, `pqvpn`, `reproduce.sh script` (+175 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 720 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **47 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VPNClient` connect `VPNClient` to `HandshakeError`, `test_crypto_protocol.py`, `client.py`, `main`, `fingerprint`, `HybridKEM`, `test_udp_bind_failure_cleans_every_resource`, `generate_server_identity`, `runtime.py`, `kemtls.py`, `ClientService`, `NetworkQualityMonitor`, `test_runtime.py`, `Security Audit — 2026-09-05`, `cli.py`?**
  _High betweenness centrality (0.059) - this node is a cross-community bridge._
- **Why does `ClientStatus` connect `ClientStatus` to `.__init__`, `IPCClient`, `identity.py`, `MainWindow`, `client.py`, `._render`, `test_client_app.py`, `FakeIPC`, `TestAccountAwareHome`, `_device_setup`, `ClientService`, `test_runtime.py`, `TestAccountGUI`?**
  _High betweenness centrality (0.054) - this node is a cross-community bridge._
- **Why does `AccountStore` connect `AccountStore` to `AuthorizedClients`, `InvalidAccountInput`, `AccountAPIConfig`, `test_client_app.py`, `accounts.py`, `test_account_api.py`, `test_accounts.py`, `create_app`, `._connection`, `cli.py`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **Are the 39 inferred relationships involving `HandshakeError` (e.g. with `test_concurrent_duplicate_replay_exactly_one_success()` and `test_cookie_response_invalid_too_short()`) actually correct?**
  _`HandshakeError` has 39 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `MainWindow` (e.g. with `TestAccountAwareHome` and `TestAccountGUI`) actually correct?**
  _`MainWindow` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 6 inferred relationships involving `AccountStore` (e.g. with `Location and permissions` and `raw_connection()`) actually correct?**
  _`AccountStore` has 6 INFERRED edges - model-reasoned connections that need verification._
- **Are the 5 inferred relationships involving `ClientService` (e.g. with `EnrollmentRequest` and `ProfileStore`) actually correct?**
  _`ClientService` has 5 INFERRED edges - model-reasoned connections that need verification._