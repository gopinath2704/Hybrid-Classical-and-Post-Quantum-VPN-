# Graph Report - Hybrid-Classical-and-Post-Quantum-VPN-  (2026-10-03)

## Corpus Check
- 44 files · ~120,750 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 24 file(s) not represented in the graph (top: (none) 12, .service 4, .toml 3)

## Summary
- 1025 nodes · 2046 edges · 71 communities (33 shown, 38 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 36 edges (avg confidence: 0.88)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `6fc86f79`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_crypto_protocol.py
- ClientHello
- HandshakeSession
- KEMTLSClientMLDSA
- TestSessionKeyStore
- KEMTLSClientV3
- TestPQCProvider
- TestKeyManager
- CookieProtector
- PQVPN Deployment
- TrafficSecrets
- MainWindow
- TestHybridKEM
- test_runtime.py
- FakeSocket
- cli.py
- reproduce.sh
- ECCProvider
- network.py
- kemtls.py
- get_crypto_status
- SessionKeyStore
- NetworkQualityMonitor
- sanitize_error
- ReplayWindow
- _compute_finished_mac
- PongFilter
- PQSignatureProvider
- parametrize
- ClientService
- doctor_run
- .revoke_session
- .__init__
- test_onboarding.py
- .send_command
- AccountClient
- HybridKEM
- client.py
- HandshakeError
- AccountSession
- ._handle_connection
- runtime.py
- PQCProvider
- KEMTLSClient
- _MockInsecurePQCProvider
- test_managed_authentication_close_has_clear_non_claiming_message
- SessionRecord
- until
- HybridKeyBundle
- TUNInterface
- MTUMonitor
- privileged_code_permissions
- pqvpn
- ServerFinishedMLDSA
- test_graceful_server_stop_has_no_exception
- .test_all_supported_algorithms
- ipv4
- test_client_rekey_protocol_uses_control_domain
- _IPCWorker
- PowerButton
- main
- ClientNetwork
- StatusRow
- NavRail

## God Nodes (most connected - your core abstractions)
1. `MainWindow` - 70 edges
2. `HandshakeError` - 50 edges
3. `ClientService` - 38 edges
4. `PQVPN Deployment` - 27 edges
5. `exchange()` - 24 edges
6. `HybridKEM` - 23 edges
7. `HandshakeSession` - 22 edges
8. `VPNClient` - 21 edges
9. `sanitize_error()` - 21 edges
10. `exchange_v3()` - 21 edges

## Surprising Connections (you probably didn't know these)
- `Packaging foundation` --references--> `PQCUnavailableError`  [INFERRED]
  docs/deployment.md → crypto/hybrid_crypto.py
- `ClientService` --uses--> `VPNClient`  [INFERRED]
  app/client.py → vpn/runtime.py
- `test_enrollment_cli_generation_and_server_authorization()` --calls--> `main()`  [EXTRACTED]
  tests/test_onboarding.py → vpn/cli.py
- `test_authorize_request_preserves_assigned_ip_validation()` --calls--> `main()`  [EXTRACTED]
  tests/test_onboarding.py → vpn/cli.py
- `test_managed_service_setup_and_narrow_ipc()` --calls--> `ClientService`  [EXTRACTED]
  tests/test_onboarding.py → app/client.py

## Import Cycles
- None detected.

## Communities (71 total, 38 thin omitted)

### Community 0 - "test_crypto_protocol.py"
Cohesion: 0.13
Nodes (20): pack_cookie_challenge(), unpack_cookie_challenge(), exchange(), header(), test_authenticated_handshake_and_directional_keys(), test_concurrent_duplicate_replay_exactly_one_success(), test_concurrent_encrypt_sequence_and_nonce_uniqueness(), test_control_and_data_sequence_domains_are_independent() (+12 more)

### Community 1 - "ClientHello"
Cohesion: 0.11
Nodes (8): ClientHello, ClientKeyExchange, ServerFinished, ServerHello, test_cookie_response_pack_unpack(), test_frozen_v2_handshake_serialization(), test_message_pack_unpack_roundtrips(), test_server_identity_key_omitted_but_fingerprint_bound()

### Community 2 - "HandshakeSession"
Cohesion: 0.27
Nodes (3): Channel, FrameType, HandshakeSession

### Community 3 - "KEMTLSClientMLDSA"
Cohesion: 0.12
Nodes (13): KEMTLSClientMLDSA, KEMTLSServerMLDSA, exchange_mldsa(), find_client(), test_mldsa_authenticated_handshake_and_directional_keys(), test_mldsa_cross_session_isolation(), test_mldsa_message_sizes(), test_mldsa_session_protocol_version_in_encrypt() (+5 more)

### Community 5 - "KEMTLSClientV3"
Cohesion: 0.12
Nodes (8): KEMTLSClientV3, KEMTLSServerV3, TranscriptHasher, test_transcript_hash_copy_and_count(), test_v3_message_sizes(), test_v3_transcript_tampering_rejected(), test_v3_unauthorized_client_rejected(), test_v3_wrong_server_fingerprint_rejected()

### Community 8 - "CookieProtector"
Cohesion: 0.15
Nodes (9): CookieProtector, test_cookie_accepted_just_before_and_after_rotation(), test_cookie_bad_length_rejected(), test_cookie_no_crash_at_boot_time(), test_cookie_protector_rotation(), test_cookie_protector_round_trip(), test_cookie_rejected_after_two_rotations(), test_cookie_wrong_ip_rejected() (+1 more)

### Community 9 - "PQVPN Deployment"
Cohesion: 0.05
Nodes (36): Arch / Omarchy, Completed validation record — 2026-09-15, Create a public server profile on the Ubuntu administrator host, Current validation record, Current validation record, Debian / Ubuntu 26.04-class, Desktop Milestone 3 managed installation, Disposable root namespace gate (+28 more)

### Community 10 - "TrafficSecrets"
Cohesion: 0.17
Nodes (6): derive_schedule_mldsa(), derive_schedule_v3(), _derive_secrets(), _expand(), TrafficSecrets, test_mldsa_key_schedule_differs_from_v3_kem()

### Community 11 - "MainWindow"
Cohesion: 0.06
Nodes (4): ClientStatus, format_duration(), MainWindow, truncate_fingerprint()

### Community 15 - "cli.py"
Cohesion: 0.10
Nodes (5): collect_sanity(), ensure_results_dir(), main(), results_dir(), run_system()

### Community 18 - "network.py"
Cohesion: 0.11
Nodes (6): connectivity(), effective_policy(), IPv6Guard, main(), preflight(), render()

### Community 19 - "kemtls.py"
Cohesion: 0.09
Nodes (14): ClientHelloMLDSA, ClientHelloV3, ClientKeyExchangeMLDSA, ClientKeyExchangeV3, Direction, _fields(), _fixed(), HandshakeState (+6 more)

### Community 20 - "get_crypto_status"
Cohesion: 0.33
Nodes (4): get_crypto_status(), test_mock_never_quantum_safe(), test_native_authenticated_session_records(), test_native_mlkem_self_test()

### Community 25 - "_compute_finished_mac"
Cohesion: 0.23
Nodes (5): _compute_finished_mac(), derive_schedule(), ServerFinishedV3, _verify_finished_mac(), test_finished_mac_labels_and_tampering()

### Community 28 - "parametrize"
Cohesion: 0.20
Nodes (9): test_invalid_profile_fields_rejected(), test_malformed_enrollment_fields_rejected(), test_profile_rejects_secret_or_executable_fields(), test_control_activity_is_counted_after_validation(), test_control_loss_restores_resources(), test_invalid_preferred_ip_rejected(), test_ipv6_mtu_safe_datagram(), test_mtu_safe_datagram() (+1 more)

### Community 29 - "ClientService"
Cohesion: 0.18
Nodes (8): ClientService, test_deleting_active_profile_returns_to_setup_required(), test_explicit_config_mode_remains_unambiguous(), test_ipc_rejects_unknown_fields_and_generic_file_writes(), test_managed_service_export_is_public_and_identity_is_stable(), test_managed_service_setup_and_narrow_ipc(), test_maximum_profile_status_fits_unchanged_ipc_limit(), test_profile_mutations_refused_while_connected()

### Community 30 - "doctor_run"
Cohesion: 0.18
Nodes (13): command(), doctor_run(), available(), check(), forwarding(), ipv6_policy(), report(), resolve() (+5 more)

### Community 32 - ".__init__"
Cohesion: 0.34
Nodes (3): Card, DataRow, gui_label()

### Community 33 - "test_onboarding.py"
Cohesion: 0.08
Nodes (8): _make_arch_source_archive(), profile_json(), profile_value(), server_public_key(), _stable_archive_digest(), test_arch_development_archive_is_checksum_verified_and_secret_free(), test_packages_do_not_include_deployment_identity_or_config(), connected()

### Community 35 - "AccountClient"
Cohesion: 0.11
Nodes (7): AccountAPIError, AccountClient, _invalid_response(), bind(), public_device_identity(), _sanitized_message(), _unavailable()

### Community 36 - "HybridKEM"
Cohesion: 0.11
Nodes (17): HybridKEM, exchange_v3(), test_rehandshake_after_rekey(), test_rehandshake_bad_secret_length_rejected(), test_rehandshake_empty_transcript_rejected(), test_rehandshake_epoch_derives_new_keys(), test_rehandshake_key_confirmation_rejects_flipped_byte(), test_rehandshake_multiple_epochs() (+9 more)

### Community 37 - "client.py"
Cohesion: 0.14
Nodes (6): account_ux_state(), ConnectionState, _launch_gui(), main(), scroll_page(), SessionState

### Community 38 - "HandshakeError"
Cohesion: 0.08
Nodes (12): HandshakeError, unpack_cookie_response(), test_cookie_response_invalid_too_short(), IPPool, recv_exact(), recv_message(), send_message(), ServerSession (+4 more)

### Community 41 - "._handle_connection"
Cohesion: 0.23
Nodes (5): get_peer_uid(), ipc_recv(), ipc_send(), _recv_exact(), test_public_enrollment_roundtrip_over_real_ipc_frame()

### Community 42 - "runtime.py"
Cohesion: 0.24
Nodes (5): pack_cookie_response(), TUNMode, configure_tun(), open_tun(), RekeyState

### Community 43 - "PQCProvider"
Cohesion: 0.14
Nodes (3): PQCProvider, test_mitm_identity_substitution_rejected(), native()

### Community 44 - "KEMTLSClient"
Cohesion: 0.27
Nodes (7): KEMTLSClient, KEMTLSServer, test_exact_reduced_handshake_sizes(), test_handshake_state_transitions(), test_transcript_tampering_rejected(), test_unauthorized_client_rejected(), test_wrong_server_fingerprint_rejected()

### Community 51 - "until"
Cohesion: 0.18
Nodes (10): test_authenticated_keepalive_prevents_idle_expiry(), test_cookie_always_mode_handshake_completes(), test_cookie_off_mode_no_challenge(), test_genuinely_idle_session_expires_and_cleans_up(), test_manual_and_automatic_rekey_during_authenticated_traffic(), test_rehandshake_after_rekey(), test_rehandshake_succeeds_and_advances_epoch(), test_rehandshake_tampered_confirmation_fails_client() (+2 more)

### Community 55 - "privileged_code_permissions"
Cohesion: 0.53
Nodes (5): privileged_code_permissions(), inspect(), inspect_metadata(), resolve_trusted_link(), visit()

### Community 59 - "test_graceful_server_stop_has_no_exception"
Cohesion: 0.40
Nodes (3): FakeTun, test_graceful_server_stop_has_no_exception(), make_socket()

### Community 61 - "ipv4"
Cohesion: 0.50
Nodes (4): ipv4(), test_delayed_rekey_keeps_data_forwarding(), test_inner_source_validation(), test_only_authorized_current_records_touch_activity()

### Community 67 - "main"
Cohesion: 0.22
Nodes (5): test_authorize_request_preserves_assigned_ip_validation(), test_enrollment_cli_generation_and_server_authorization(), _account_command(), main(), _parser()

### Community 68 - "ClientNetwork"
Cohesion: 0.42
Nodes (3): ClientNetwork, RouteUndo, run_ip()

## Knowledge Gaps
- **32 isolated node(s):** `HandshakeState`, `RekeyState`, `reproduce.sh script`, `pqvpn`, `Arch / Omarchy` (+27 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 375 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **38 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MainWindow` connect `MainWindow` to `.__init__`, `AccountClient`, `client.py`?**
  _High betweenness centrality (0.131) - this node is a cross-community bridge._
- **Why does `VPNClient` connect `HandshakeError` to `main`, `client.py`, `runtime.py`, `cli.py`, `NetworkQualityMonitor`, `sanitize_error`, `ClientService`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Why does `HandshakeError` connect `HandshakeError` to `test_crypto_protocol.py`, `ClientHello`, `HandshakeSession`, `AccountClient`, `KEMTLSClientMLDSA`, `KEMTLSClientV3`, `TrafficSecrets`, `runtime.py`, `test_runtime.py`, `kemtls.py`, `ReplayWindow`, `_compute_finished_mac`, `ServerFinishedMLDSA`?**
  _High betweenness centrality (0.051) - this node is a cross-community bridge._
- **What connects `HandshakeState`, `RekeyState`, `reproduce.sh script` to the rest of the system?**
  _32 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `test_crypto_protocol.py` be split into smaller, more focused modules?**
  _Cohesion score 0.13105413105413105 - nodes in this community are weakly interconnected._
- **Should `ClientHello` be split into smaller, more focused modules?**
  _Cohesion score 0.11428571428571428 - nodes in this community are weakly interconnected._
- **Should `KEMTLSClientMLDSA` be split into smaller, more focused modules?**
  _Cohesion score 0.12105263157894737 - nodes in this community are weakly interconnected._