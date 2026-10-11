# Graph Report - Hybrid-Classical-and-Post-Quantum-VPN-  (2026-10-03)

## Corpus Check
- 44 files · ~120,417 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 24 file(s) not represented in the graph (top: (none) 12, .service 4, .toml 3)

## Summary
- 1890 nodes · 4493 edges · 118 communities (76 shown, 42 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 337 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `75597768`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_crypto_protocol.py
- benchmarks.py
- HandshakeSession
- PQSignatureProvider
- TestSessionKeyStore
- KEMTLSClientV3
- TestPQCProvider
- TestKeyManager
- CookieProtector
- PQVPN Deployment
- kemtls.py
- MainWindow
- TestHybridKEM
- test_runtime.py
- FakeSocket
- run_all.py
- reproduce.sh
- ECCProvider
- runtime.py
- _pack_header
- test_account_api.py
- SessionKeyStore
- NetworkQualityMonitor
- sanitize_error
- test_accounts.py
- account_api.py
- PongFilter
- _MockInsecureSigProvider
- ProfileError
- ClientService
- doctor_run
- identity.py
- .__init__
- test_onboarding.py
- IPCClient
- AccountAPIError
- HybridKEM
- test_client_app.py
- HandshakeError
- hybrid_crypto.py
- AccountSession
- ipc_recv
- test_networking.py
- PQCProvider
- fingerprint
- _MockInsecurePQCProvider
- _socket_path
- test_managed_authentication_close_has_clear_non_claiming_message
- SessionRecord
- ClientStatus
- Path
- VPNServer
- HybridKeyBundle
- TUNInterface
- MTUMonitor
- test_deployment.py
- pqvpn
- AccountStore
- UserRecord
- Security Audit — 2026-09-05
- TestAccountGUI
- VPNClient
- AccountClient
- _IPCWorker
- PowerButton
- AuthorizedClients
- ClientNetwork
- accounts.py
- NavRail
- ._connection
- create_app
- _device_setup
- Path
- ClientConfig
- Auto-routing rules
- PQVPN Design
- PQ-VPN
- TestECCProvider
- run_pqvpn.py
- datetime
- Tun
- test_udp_bind_failure_cleans_every_resource
- PacketOverheadAnalyzer
- generate_tables.py
- Reproducibility Artifact
- fail
- BoundedRateLimiter
- Formal verification
- IPPool
- ServerSession
- AccountAPIConfigError
- namespace_vpn.sh
- _sanitized_message
- Desktop Milestone 3 managed installation
- Encrypted frame
- Quick start
- /dev — Toolchain Status & Override
- PQCUnavailableError
- test_real_namespace_tunnel
- verify_formal.sh
- Expected outputs
- Running the server
- bench_netem.sh
- Milestone 3 live validation: Omarchy client + Ubuntu VM
- Legacy explicit-TOML client setup
- Pre-VPS Validation Handoff
- run_wireguard.sh
- install-liboqs.sh
- server-network.sh
- test_chunked_oversized_body_is_rejected_without_content_length

## God Nodes (most connected - your core abstractions)
1. `HandshakeError` - 89 edges
2. `MainWindow` - 79 edges
3. `fingerprint()` - 62 edges
4. `AccountStore` - 60 edges
5. `ClientService` - 53 edges
6. `ClientStatus` - 45 edges
7. `AccountClient` - 45 edges
8. `VPNClient` - 43 edges
9. `HybridKEM` - 41 edges
10. `AuthorizedClients` - 41 edges

## Surprising Connections (you probably didn't know these)
- `A-03 — Legacy/ambiguous PQC selection and unsafe wire choices` --references--> `PQCProvider`  [INFERRED]
  docs/security_audit.md → crypto/hybrid_crypto.py
- `A-13 — Handshake parsers accept inconsistent/trailing data` --references--> `_unpack_header()`  [INFERRED]
  docs/security_audit.md → handshake/kemtls.py
- ``.pqenroll` schema` --references--> `AuthorizedClients`  [INFERRED]
  docs/design.md → vpn/identity.py
- `2026-09-05 focused follow-up findings` --references--> `ClientNetwork`  [INFERRED]
  docs/security_audit.md → vpn/runtime.py
- `Packaging foundation` --references--> `PQCUnavailableError`  [INFERRED]
  docs/deployment.md → crypto/hybrid_crypto.py

## Import Cycles
- None detected.

## Communities (118 total, 42 thin omitted)

### Community 0 - "test_crypto_protocol.py"
Cohesion: 0.10
Nodes (28): Channel, FrameType, exchange(), exchange_mldsa(), find_client(), header(), test_authenticated_handshake_and_directional_keys(), test_concurrent_duplicate_replay_exactly_one_success() (+20 more)

### Community 1 - "benchmarks.py"
Cohesion: 0.13
Nodes (15): collect_environment(), _cpu_model(), _git_commit(), _liboqs_version(), main(), _results_dir_for_run(), run_full_suite(), SuiteSummary (+7 more)

### Community 2 - "HandshakeSession"
Cohesion: 0.08
Nodes (9): A-01 — Server is not authenticated, _compute_finished_mac(), HandshakeSession, ReplayWindow, ServerFinishedMLDSA, ServerFinishedV3, _verify_finished_mac(), test_finished_mac_labels_and_tampering() (+1 more)

### Community 3 - "PQSignatureProvider"
Cohesion: 0.11
Nodes (12): HandshakeBenchmark, HandshakeMetric, PQSignatureProvider, _make_mldsa(), KEMTLSClientMLDSA, KEMTLSServerMLDSA, test_mldsa_message_sizes(), test_mldsa_transcript_tampering_rejected() (+4 more)

### Community 5 - "KEMTLSClientV3"
Cohesion: 0.15
Nodes (10): _make_v3(), ClientHelloV3, ClientKeyExchangeV3, KEMTLSClientV3, KEMTLSServerV3, ServerHelloV3, test_v3_message_sizes(), test_v3_transcript_tampering_rejected() (+2 more)

### Community 8 - "CookieProtector"
Cohesion: 0.23
Nodes (6): CookieProtector, test_cookie_bad_length_rejected(), test_cookie_protector_rotation(), test_cookie_protector_round_trip(), test_cookie_wrong_ip_rejected(), test_cookie_wrong_port_rejected()

### Community 9 - "PQVPN Deployment"
Cohesion: 0.09
Nodes (22): Current validation record, Current validation record, Disposable root namespace gate, DNS policy, Exact tested dependencies, Firewall policy and subnet selection, Install and provision, then diagnose, Linux VPS deployment gate (+14 more)

### Community 10 - "kemtls.py"
Cohesion: 0.09
Nodes (11): KeyManager, _secure_zero(), derive_schedule(), derive_schedule_mldsa(), derive_schedule_v3(), _derive_secrets(), Direction, _expand() (+3 more)

### Community 11 - "MainWindow"
Cohesion: 0.08
Nodes (4): format_duration(), MainWindow, bind(), truncate_fingerprint()

### Community 13 - "test_runtime.py"
Cohesion: 0.13
Nodes (21): A-17 — Resource exhaustion controls are insufficient, ipv4(), test_authenticated_keepalive_prevents_idle_expiry(), test_control_activity_is_counted_after_validation(), test_control_loss_restores_resources(), test_cookie_always_mode_handshake_completes(), test_delayed_rekey_keeps_data_forwarding(), test_genuinely_idle_session_expires_and_cleans_up() (+13 more)

### Community 14 - "FakeSocket"
Cohesion: 0.14
Nodes (4): FakeSocket, FakeTun, test_graceful_server_stop_has_no_exception(), make_socket()

### Community 15 - "run_all.py"
Cohesion: 0.29
Nodes (4): collect_sanity(), main(), results_dir(), run_system()

### Community 18 - "runtime.py"
Cohesion: 0.09
Nodes (7): _launch_gui(), main(), connectivity(), effective_policy(), IPv6Guard, preflight(), RekeyState

### Community 19 - "_pack_header"
Cohesion: 0.11
Nodes (10): ClientHelloMLDSA, ClientKeyExchangeMLDSA, _fields(), _fixed(), MessageType, _pack_header(), ServerHelloMLDSA, _unpack_header() (+2 more)

### Community 20 - "test_account_api.py"
Cohesion: 0.13
Nodes (32): bearer(), bind(), device_identity(), login(), raw_connection(), register(), test_bind_device_records_public_identity_only(), test_concurrent_sessions_and_revoke_all_store_operation() (+24 more)

### Community 22 - "NetworkQualityMonitor"
Cohesion: 0.11
Nodes (4): test_quality_metrics_jitter_loss_reset(), test_quality_rolling_window(), NetworkQualityMonitor, QualitySnapshot

### Community 24 - "test_accounts.py"
Cohesion: 0.09
Nodes (31): `POST /auth/register`, _cli(), public_identity(), raw_connection(), review(), store(), test_account_mutations_never_change_vpn_authorization(), test_add_and_list_multiple_devices() (+23 more)

### Community 25 - "account_api.py"
Cohesion: 0.09
Nodes (20): AuthenticatedContext, BodyLimitMiddleware, bind_device(), database_error(), internal_error(), list_devices(), login(), register() (+12 more)

### Community 28 - "ProfileError"
Cohesion: 0.16
Nodes (15): test_invalid_profile_fields_rejected(), test_profile_rejects_secret_or_executable_fields(), test_profile_store_bound_keeps_ipc_responses_small(), test_profile_store_corruption_and_exact_deletion(), test_profile_store_duplicate_requires_explicit_replace(), test_profile_store_rejects_symlink_state(), _atomic_write(), _decode_json() (+7 more)

### Community 29 - "ClientService"
Cohesion: 0.15
Nodes (3): ClientService, TestClientService, TestMalformedIPC

### Community 30 - "doctor_run"
Cohesion: 0.16
Nodes (15): test_doctor_production_scope(), test_doctor_reports_privileged_code_failure(), command(), doctor_run(), available(), check(), database(), forwarding() (+7 more)

### Community 31 - "identity.py"
Cohesion: 0.14
Nodes (16): test_authorize_request_preserves_assigned_ip_validation(), test_enrollment_size_duplicate_key_and_output_symlink_rejected(), test_malformed_enrollment_fields_rejected(), main(), _parser(), _bounded_bytes(), EnrollmentError, EnrollmentRequest (+8 more)

### Community 32 - ".__init__"
Cohesion: 0.19
Nodes (6): Card, DataRow, gui_label(), MetricCard, scroll_page(), StatusRow

### Community 33 - "test_onboarding.py"
Cohesion: 0.09
Nodes (23): ConnectionState, _make_arch_source_archive(), profile_json(), profile_value(), server_public_key(), _stable_archive_digest(), test_arch_development_archive_is_checksum_verified_and_secret_free(), test_deleting_active_profile_returns_to_setup_required() (+15 more)

### Community 35 - "AccountAPIError"
Cohesion: 0.14
Nodes (3): AccountAPIError, _invalid_response(), _unavailable()

### Community 36 - "HybridKEM"
Cohesion: 0.11
Nodes (17): HybridKEM, exchange_v3(), test_rehandshake_after_rekey(), test_rehandshake_bad_secret_length_rejected(), test_rehandshake_empty_transcript_rejected(), test_rehandshake_epoch_derives_new_keys(), test_rehandshake_key_confirmation_rejects_flipped_byte(), test_rehandshake_multiple_epochs() (+9 more)

### Community 37 - "test_client_app.py"
Cohesion: 0.15
Nodes (8): account_ux_state(), public_device_identity(), SessionState, _pyside6_available(), qapp(), test_error_sanitization_is_bounded_and_redacts_secrets(), TestAccountUXState, TestPublicDeviceIdentity

### Community 38 - "HandshakeError"
Cohesion: 0.19
Nodes (12): HandshakeError, pack_cookie_challenge(), pack_cookie_response(), unpack_cookie_challenge(), unpack_cookie_response(), test_cookie_challenge_pack_unpack(), test_cookie_challenge_v3_version(), test_cookie_response_invalid_too_short() (+4 more)

### Community 40 - "AccountSession"
Cohesion: 0.14
Nodes (3): AccountSession, UserProfile, TestAccountSession

### Community 41 - "ipc_recv"
Cohesion: 0.11
Nodes (6): get_peer_uid(), ipc_recv(), ipc_send(), _recv_exact(), TestIPCFraming, test_public_enrollment_roundtrip_over_real_ipc_frame()

### Community 42 - "test_networking.py"
Cohesion: 0.13
Nodes (14): test_obsolete_udp_setting_rejected(), test_actual_client_cleanup_removes_guard(), test_config_paths_resolve_from_toml_not_cwd(), test_doctor_ipv6_is_read_only(), test_exact_mtu_calculation(), test_namespace_route_snapshot_ignores_only_async_kernel_link_local_routes(), test_native_installer_verifies_commit_before_build(), test_omitted_identity_paths_resolve_beside_toml() (+6 more)

### Community 43 - "PQCProvider"
Cohesion: 0.13
Nodes (5): PQCProvider, identities(), mldsa_identities(), v3_identities(), native()

### Community 44 - "fingerprint"
Cohesion: 0.13
Nodes (14): _make_v2(), KEMTLSClient, KEMTLSServer, TranscriptHasher, test_exact_reduced_handshake_sizes(), test_handshake_state_transitions(), test_mitm_identity_substitution_rejected(), test_server_identity_key_omitted_but_fingerprint_bound() (+6 more)

### Community 49 - "ClientStatus"
Cohesion: 0.12
Nodes (4): ClientStatus, TestClientStatus, TestGUIHeadless, test_client_status_serialization_and_real_schema()

### Community 50 - "Path"
Cohesion: 0.10
Nodes (4): ChartGenerator, PayloadResult, ThroughputBenchmark, test_throughput_benchmark_frame_size()

### Community 51 - "VPNServer"
Cohesion: 0.17
Nodes (10): A-07 — UDP endpoint negotiation is functionally broken, A-09 — No real host/client routing lifecycle, test_client_private_permissions(), test_server_identity_pair_and_permissions(), connected(), test_cookie_off_mode_no_challenge(), test_server_session_timeout_disconnects_client(), generate_client_identity() (+2 more)

### Community 53 - "TUNInterface"
Cohesion: 0.13
Nodes (9): A-10 — Production silently falls back to an emulated TUN, open_pipe(), test_closed_tun_errors(), test_tun_defaults_and_metadata(), test_tun_lifecycle_and_roundtrip(), TUNInterface, TUNMode, configure_tun() (+1 more)

### Community 55 - "test_deployment.py"
Cohesion: 0.08
Nodes (20): db(), firewall_commands(), staged_privileged_tree(), test_bad_server_config_fails_before_tun(), test_database_rejects_malformed_and_conflicting(), test_dns_fail_safe_and_restore(), test_doctor_is_read_only_and_reports_failures(), test_forwarding_restore_and_reconcile() (+12 more)

### Community 58 - "AccountStore"
Cohesion: 0.14
Nodes (11): Location and permissions, test_session_store_validates_inputs_and_expiry(), test_session_store_validation_touch_interval_and_revocation(), test_current_version_with_incompatible_layout_fails(), test_database_does_not_repermission_an_unsafe_shared_directory(), test_newer_schema_version_fails_closed(), test_unversioned_nonempty_database_is_not_silently_migrated(), AccountDatabaseError (+3 more)

### Community 59 - "UserRecord"
Cohesion: 0.13
Nodes (11): test_password_hash_helpers_fail_safely_and_detect_rehash(), test_password_hash_is_argon2id_and_plaintext_is_never_stored(), test_password_length_boundaries_and_no_secret_in_errors(), test_version_1_database_migrates_with_devices_pending(), hash_password(), needs_rehash(), normalize_email(), normalize_username() (+3 more)

### Community 60 - "Security Audit — 2026-09-05"
Cohesion: 0.09
Nodes (21): 2026-09-05 focused follow-up findings, A-02 — Clients are not authenticated or authorized, A-03 — Legacy/ambiguous PQC selection and unsafe wire choices, A-04 — Non-directional key schedule, A-05 — AES-GCM nonce construction and replay handling are unsafe, A-06 — Rekey cannot synchronize, A-11 — MTU accounting is incorrect and unapplied, A-12 — Telemetry is labelled real but never sampled on the tunnel (+13 more)

### Community 61 - "TestAccountGUI"
Cohesion: 0.14
Nodes (3): TestAccountAwareHome, TestAccountGUI, TestDeviceBindingGUI

### Community 62 - "VPNClient"
Cohesion: 0.17
Nodes (9): IPC boundary, Managed desktop onboarding, `.pqenroll` schema, `.pqvpn` schema, test_fail_policy_rejects_before_tun_or_routing(), test_automatic_rekey_short_interval(), test_client_rekey_protocol_uses_control_domain(), test_overlapping_rekey_rejected() (+1 more)

### Community 63 - "AccountClient"
Cohesion: 0.14
Nodes (4): AccountClient, TestAccountClientConstruction, TestAccountClientLiveAPI, TestAccountClientMalformedResponses

### Community 67 - "AuthorizedClients"
Cohesion: 0.08
Nodes (19): Account storage, authentication, and device binding (Milestone 4), Administrator device approval (Milestone 4.5), Authentication API, Desktop client, `GET /auth/me`, `GET /devices` and `POST /devices`, HTTPS configuration and service, Input and password policy (+11 more)

### Community 68 - "ClientNetwork"
Cohesion: 0.22
Nodes (10): NativeTun, network(), test_fail_policy_with_no_ipv6_does_not_install_guard(), test_failed_atomic_block_does_not_touch_routes_or_unrelated_tables(), test_full_tunnel_blocks_ipv6_including_existing_flows_and_forwarding(), test_guard_removed_even_if_dns_undo_raises(), test_policy_defaults_and_explicit_split_block(), ClientNetwork (+2 more)

### Community 69 - "accounts.py"
Cohesion: 0.12
Nodes (7): test_invalid_email_rejected(), test_invalid_username_rejected(), AccountError, InvalidAccountInput, PasswordHashError, _validate_device_name(), _validate_public_identity()

### Community 70 - "NavRail"
Cohesion: 0.25
Nodes (3): NavButton, NavRail, SummaryBlock

### Community 71 - "._connection"
Cohesion: 0.26
Nodes (6): AccountNotFound, DeviceRecord, _utc_now(), _validate_device_status(), _validate_enabled(), _validate_id()

### Community 72 - "create_app"
Cohesion: 0.15
Nodes (16): app(), client(), config(), test_login_rate_limit_is_source_scoped(), test_login_rate_limit_returns_429_retry_after_and_is_identifier_scoped(), test_registration_never_changes_vpn_authorization(), test_remote_or_implicit_cleartext_bind_fails_closed(), test_successful_login_resets_failed_attempts() (+8 more)

### Community 73 - "_device_setup"
Cohesion: 0.12
Nodes (3): _device_setup(), FakeIPC, IdentityIPC

### Community 74 - "Path"
Cohesion: 0.18
Nodes (10): test_enrollment_roundtrip_is_public_only(), _atomic_new(), client_public_identity(), ensure_client_identity(), load_client_kem_private(), load_client_private(), _read_client_public(), read_private() (+2 more)

### Community 75 - "ClientConfig"
Cohesion: 0.21
Nodes (15): test_client_options_validate(), test_firewall_order_and_scope(), test_unknown_policy_rejected(), test_configuration_defaults_are_safe(), test_server_ip_pinned_for_all_paths(), resolve(), addresses(), ClientConfig (+7 more)

### Community 76 - "Auto-routing rules"
Cohesion: 0.12
Nodes (15): Always-on rules, API design (API, endpoint, interface, protocol, message format), Asking about the codebase (how does X work, where is Y, what calls Z, explain the architecture), Auto-routing rules, Bug fix (fix, broken, error, crash, failing test, doesn't work, regression), Code review (review, check this, look at, PR, before merge, is this correct), Debugging (debug, trace, why does, unexpected, investigate), Documentation (document, explain, ADR, decision record) (+7 more)

### Community 77 - "PQVPN Design"
Cohesion: 0.12
Nodes (16): Authentication boundary, Benchmarking and measurement harness, Cryptographic and Protocol Design, D1: Client authentication flow for v3, D6: Data-plane implementation scope, Deployment and diagnostics, Deployment boundaries, Design decisions (+8 more)

### Community 78 - "PQ-VPN"
Cohesion: 0.13
Nodes (15): Architecture, Client enrollment, Cryptography, Current status, Desktop client, Docker, Documentation, Features (+7 more)

### Community 80 - "run_pqvpn.py"
Cohesion: 0.24
Nodes (9): collect_sanity(), evaluate_suite(), HandshakeResult, main(), measure_encrypt_throughput(), measure_handshakes_per_sec(), measure_memory_per_session(), run_handshake() (+1 more)

### Community 81 - "datetime"
Cohesion: 0.31
Nodes (4): _parse_timestamp(), SessionRecord, _utc_timestamp(), _validate_token_hash()

### Community 82 - "Tun"
Cohesion: 0.18
Nodes (7): kernel(), ip(), process(), test_exact_previous_route_restoration(), test_partial_dns_failure_always_reverts(), test_route_apply_failure_rolls_back(), Tun

### Community 84 - "PacketOverheadAnalyzer"
Cohesion: 0.18
Nodes (4): LayerOverhead, PacketEfficiencyResult, PacketOverheadAnalyzer, test_packet_overhead_output()

### Community 85 - "generate_tables.py"
Cohesion: 0.25
Nodes (4): generate(), load_pqvpn(), main(), text_table()

### Community 86 - "Reproducibility Artifact"
Cohesion: 0.18
Nodes (11): Baseline VPN comparison (optional), Expected runtime, Hardware requirements, One-command setup, Option A: Docker (recommended), Option B: Native, Pinned versions, Regenerating figures from raw data (+3 more)

### Community 87 - "fail"
Cohesion: 0.25
Nodes (10): IPv6 policy, IPv6 leakage and revocation boundaries, Unsupported IPv6 and revocation, Changes and boundaries, Current validation matrix, Pre-VPS hardening — 2026-09-07, Source-review continuation, fail() (+2 more)

### Community 88 - "BoundedRateLimiter"
Cohesion: 0.27
Nodes (3): test_limiter_is_monotonic_bounded_and_removes_stale_entries(), BoundedRateLimiter, _RateEntry

### Community 89 - "Formal verification"
Cohesion: 0.22
Nodes (9): Assumptions, Expected output, Formal verification, Hybrid security argument, Model structure, Prerequisites, Recorded run, Running (+1 more)

### Community 90 - "IPPool"
Cohesion: 0.25
Nodes (4): test_static_leases_are_reserved_from_dynamic_allocations(), test_ip_pool_allocation_release(), test_static_ip_duplicate_prevention(), IPPool

### Community 91 - "ServerSession"
Cohesion: 0.31
Nodes (4): A-08 — Server architecture cannot support real multi-client routing, test_session_clock_is_monotonic(), ServerSession, SessionManager

### Community 92 - "AccountAPIConfigError"
Cohesion: 0.36
Nodes (4): test_dedicated_config_loads_relative_paths_and_rejects_unknown_values(), AccountAPIConfigError, load_account_api_config(), _validate_tls_file()

### Community 94 - "namespace_vpn.sh"
Cohesion: 0.57
Nodes (6): cleanup(), filter_meaningful_ipv6_routes(), namespace_vpn.sh script, snapshot_meaningful_ipv6_routes(), start_client(), wait_bounded()

### Community 96 - "Desktop Milestone 3 managed installation"
Cohesion: 0.33
Nodes (6): Arch / Omarchy, Create a public server profile on the Ubuntu administrator host, Debian / Ubuntu 26.04-class, Desktop Milestone 3 managed installation, Offline enrollment administration, Packaging foundation

### Community 97 - "Encrypted frame"
Cohesion: 0.33
Nodes (6): Authentication boundary, Encrypted frame, Hybrid re-handshake (post-compromise security), Protocol v3, Protocol v3-mldsa (comparison suite), Stateless cookie (DoS resistance)

### Community 98 - "Quick start"
Cohesion: 0.33
Nodes (6): 1. Install native liboqs, 2. Set up the Python environment, 3. Generate identities, 4. Configure and run, Prerequisites, Quick start

### Community 100 - "/dev — Toolchain Status & Override"
Cohesion: 0.40
Nodes (4): /dev — Toolchain Status & Override, Notes, When invoked with args, When invoked with no args

### Community 103 - "verify_formal.sh"
Cohesion: 0.50
Nodes (4): check_results(), HS_LEMMAS, PCS_LEMMAS, verify_formal.sh script

### Community 104 - "Expected outputs"
Cohesion: 0.50
Nodes (4): Evaluation results, Expected outputs, Expected wire sizes (deterministic), Test suite

### Community 105 - "Running the server"
Cohesion: 0.67
Nodes (3): Option 1: Systemd (recommended), Option 2: Direct CLI, Running the server

## Knowledge Gaps
- **135 isolated node(s):** `run_wireguard.sh script`, `Direction`, `HandshakeState`, `pqvpn`, `reproduce.sh script` (+130 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 619 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **42 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MainWindow` connect `MainWindow` to `._add_gui_event`, `.__init__`, `test_client_app.py`, `_device_setup`, `ClientStatus`, `runtime.py`, `TestAccountGUI`, `._submit_account`?**
  _High betweenness centrality (0.095) - this node is a cross-community bridge._
- **Why does `VPNClient` connect `VPNClient` to `test_crypto_protocol.py`, `HybridKEM`, `KEMTLSClientV3`, `HandshakeError`, `ClientConfig`, `fingerprint`, `test_runtime.py`, `runtime.py`, `test_udp_bind_failure_cleans_every_resource`, `VPNServer`, `_pack_header`, `NetworkQualityMonitor`, `sanitize_error`, `ClientService`, `identity.py`?**
  _High betweenness centrality (0.083) - this node is a cross-community bridge._
- **Why does `AuthorizedClients` connect `AuthorizedClients` to `test_onboarding.py`, `create_app`, `test_networking.py`, `ClientConfig`, `fingerprint`, `test_runtime.py`, `runtime.py`, `VPNServer`, `test_account_api.py`, `doctor_run`, `test_deployment.py`, `test_accounts.py`, `VPNClient`, `identity.py`?**
  _High betweenness centrality (0.067) - this node is a cross-community bridge._
- **Are the 38 inferred relationships involving `HandshakeError` (e.g. with `test_concurrent_duplicate_replay_exactly_one_success()` and `test_cookie_response_invalid_too_short()`) actually correct?**
  _`HandshakeError` has 38 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `MainWindow` (e.g. with `TestAccountAwareHome` and `TestAccountGUI`) actually correct?**
  _`MainWindow` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 6 inferred relationships involving `AccountStore` (e.g. with `Location and permissions` and `raw_connection()`) actually correct?**
  _`AccountStore` has 6 INFERRED edges - model-reasoned connections that need verification._
- **Are the 5 inferred relationships involving `ClientService` (e.g. with `EnrollmentRequest` and `ProfileStore`) actually correct?**
  _`ClientService` has 5 INFERRED edges - model-reasoned connections that need verification._