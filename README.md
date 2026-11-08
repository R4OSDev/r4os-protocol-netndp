# NETNDP

IPv6 neighbor discovery and neighbor state.

NETNDP validates ICMPv6 ND and owns the bounded neighbor cache:8 exact links
and64 neighbors. ICMPv6 checksums are delegated through the declared
net.icmpv6 dependency. The IPv6 owner applies validated address/router/prefix
proposals; there is no second route catalogue in this provider.

Validation checks checksum, hop255, code0, scopes, targets and whole options.
RA output contains up to8 complete prefix options or returns Capacity before
mutation. Fragmented ND is rejected before cache admission. Unknown complete
options are ignored; Redirect does not install a route.

INCOMPLETE, REACHABLE, STALE, DELAY and PROBE use the actual source clock and
interface epoch. Probe counters and deadlines advance only after explicit
confirmation of successful link TX. There are at most3 probes, a5-second
DELAY and randomized reachable time from the existing entropy source. Missing
entropy keeps the provider loadable but does not admit timed neighbor work.
Clock changes retire exact affected state without rebasing deadlines.
Unsolicited NA does not allocate neighbors; capacity does not evict unrelated
pending work. Exact link reset retires only that link generation.

Build with `Build.sh` on Linux or `Build.bat` on Windows; `test` runs the
bounded component cases. `module.R4MF` owns module version, imports, profile,
dependencies and image placement. The pinned SDK selects the platform contract.

Normative contract: `Repositories/Contract/API/Ipv6Providers.txt` in the R4OS
workspace. `DOCUMENTATION.de.txt` records the provider boundary. Host codec,
controlled guest/peer and physical NIC/IRQ/DMA qualifications are separate.
Existing applications keep their current imports and operation.
