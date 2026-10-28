# Phase 0 baseline: M1 caveat

The `pqvpn-net` M1 rows for metro, continent, lossy and mtu-1280 are resumed connects: `run_pqvpn_net.sh` never removed the resumption ticket, so runs 1-29 reused the ticket saved by run 0.
True cold connect is run 0 in the raw CSVs (metro 462 ms, continent 1364 ms) or `full_connect_ms` in `resumption-*.csv`. LAN is unaffected (RTT ≈ 0).
Fixed in Phase 1, which also changed the poll interval, so Phase 1 M1 numbers are not directly comparable with these rows.
