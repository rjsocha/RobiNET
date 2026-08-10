package hub

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ErrPoolExhausted is returned when a prefix has no free address left.
var ErrPoolExhausted = errors.New("address pool exhausted")

// allocate hands out a sticky address inside the instance's prefix. The same
// fingerprint always gets the same address, so a connector that re-enrolls does
// not drift across the pool.
//
// Tenants come up from the bottom, after the lighthouse at .1 and the owner at
// .2. Connectors come down from the top. So an address says which kind of
// member holds it, which is worth more than it costs while an instance holds
// far more addresses than anybody puts in it.
func allocate(inst *Instance, fingerprint, kind string) (netip.Addr, error) {
	if inst.Allocations == nil {
		inst.Allocations = map[string]netip.Addr{}
	}

	addr, err := fromPool(inst.Overlay, inst.Allocations, fingerprint, kind,
		append(memberAddresses(inst, false), inst.LighthouseAddress, inst.TenantAddress)...)
	if err != nil {
		return netip.Addr{}, err
	}

	inst.Allocations[fingerprint] = addr
	return addr, nil
}

// allocate6 is allocate over the instance's IPv6 prefix, and it is a pool of
// its own rather than a mirror of the IPv4 one.
//
// A member's two addresses used to carry the same host number, which read
// nicely and cost too much: the smaller pool decided how many members an
// instance could hold, and a connector carrying nothing but IPv6 still spent an
// IPv4 address it would never use.
func allocate6(inst *Instance, fingerprint, kind string) (netip.Addr, error) {
	if !inst.Overlay6.IsValid() {
		return netip.Addr{}, nil
	}

	if inst.Allocations6 == nil {
		inst.Allocations6 = map[string]netip.Addr{}
	}

	addr, err := fromPool(inst.Overlay6, inst.Allocations6, fingerprint, kind,
		append(memberAddresses(inst, true), inst.LighthouseAddress6, inst.TenantAddress6)...)
	if err != nil {
		return netip.Addr{}, err
	}

	inst.Allocations6[fingerprint] = addr
	return addr, nil
}

// memberAddresses is what is already handed out according to the members
// themselves, rather than according to the allocation map.
//
// The two agree, until they do not: an instance addressed before the two
// families were separate holds members whose IPv6 address was derived from
// their IPv4 one and was never written down as an allocation. Reading the
// members costs nothing and means no address is handed out twice.
func memberAddresses(inst *Instance, six bool) []netip.Addr {
	out := make([]netip.Addr, 0, len(inst.Members))
	for _, m := range inst.Members {
		if six {
			out = append(out, m.Address6.Addr())
			continue
		}
		out = append(out, m.Address.Addr())
	}
	return out
}

// fromPool is the part both families share: sticky by fingerprint, connectors
// from the top and everybody else from the bottom.
func fromPool(prefix netip.Prefix, held map[string]netip.Addr, fingerprint, kind string, reserved ...netip.Addr) (netip.Addr, error) {
	if addr, ok := held[fingerprint]; ok {
		return addr, nil
	}

	taken := make(map[netip.Addr]struct{}, len(held)+len(reserved))
	for _, addr := range held {
		taken[addr] = struct{}{}
	}
	for _, addr := range reserved {
		if addr.IsValid() {
			taken[addr] = struct{}{}
		}
	}

	if kind == KindConnector {
		return highestFree(prefix, taken)
	}
	return lowestFree(prefix, taken)
}

// lowestFree returns the first address in the prefix that is not taken,
// skipping the network address itself and, for IPv4, the broadcast address.
func lowestFree(prefix netip.Prefix, taken map[netip.Addr]struct{}) (netip.Addr, error) {
	if !prefix.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid prefix")
	}

	addr := prefix.Masked().Addr().Next()
	for prefix.Contains(addr) {
		if _, used := taken[addr]; !used && !isBroadcast(prefix, addr) {
			return addr, nil
		}
		addr = addr.Next()
	}

	return netip.Addr{}, ErrPoolExhausted
}

// highestFree returns the last address in the prefix that is not taken.
//
// The two walks meet in the middle rather than at a boundary, so running out
// is not "the prefix ended" but "the other kind reached us", and the error has
// to say which kind ran out - that is what tells an owner whether to renumber
// or to stop admitting.
func highestFree(prefix netip.Prefix, taken map[netip.Addr]struct{}) (netip.Addr, error) {
	if !prefix.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid prefix")
	}

	addr := lastAddr(prefix)
	if !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid prefix")
	}

	// Skip the broadcast address, and then walk down while we are still inside.
	for prefix.Contains(addr) {
		if _, used := taken[addr]; !used && !isBroadcast(prefix, addr) && addr != prefix.Masked().Addr() {
			return addr, nil
		}
		addr = addr.Prev()
	}

	return netip.Addr{}, fmt.Errorf("%w: no address left for a connector", ErrPoolExhausted)
}

// lastAddr is the highest address a prefix contains.
func lastAddr(prefix netip.Prefix) netip.Addr {
	base := prefix.Masked().Addr()
	bits := base.BitLen()

	raw := base.As16()
	// The host bits are the ones below the prefix length, counted from the end
	// of the 16 byte form so both families are the same code.
	for i := 0; i < bits-prefix.Bits(); i++ {
		byteIndex := 15 - i/8
		raw[byteIndex] |= 1 << (i % 8)
	}

	out, ok := netip.AddrFromSlice(raw[:])
	if !ok {
		return netip.Addr{}
	}
	if base.Is4() {
		out = out.Unmap()
	}
	return out
}

// isBroadcast reports whether addr is the all ones address of an IPv4 prefix.
func isBroadcast(prefix netip.Prefix, addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	if prefix.Bits() >= 31 {
		return false
	}

	next := addr.Next()
	return !next.IsValid() || !prefix.Contains(next)
}

// nextSubnet steps to the subnet of the given size that follows prefix.
func nextSubnet(prefix netip.Prefix, size int) (netip.Prefix, bool) {
	addr := prefix.Masked().Addr()
	bits := addr.BitLen()
	if size < 0 || size > bits {
		return netip.Prefix{}, false
	}

	// The subnet index lives in the bits above the host part, so adding one
	// there is the same as stepping to the next subnet of that size. Working
	// on the 16 byte form keeps this identical for both families.
	raw := addr.As16()
	shift := bits - size
	byteIndex := 16 - 1 - (shift / 8)
	bitIndex := shift % 8

	carry := byte(1) << bitIndex
	for i := byteIndex; i >= 0; i-- {
		sum := uint16(raw[i]) + uint16(carry)
		raw[i] = byte(sum)
		if sum <= 0xff {
			carry = 0
			break
		}
		carry = 1
	}
	if carry != 0 {
		return netip.Prefix{}, false
	}

	next, ok := netip.AddrFromSlice(raw[:])
	if !ok {
		return netip.Prefix{}, false
	}
	if addr.Is4() {
		next = next.Unmap()
	}

	return netip.PrefixFrom(next, size), true
}

// Pool is one address space instances are carved out of, and how big a slice
// each one gets.
type Pool struct {
	Prefix netip.Prefix
	Size   int
}

func (p Pool) String() string { return fmt.Sprintf("%s in /%d", p.Prefix, p.Size) }

// allocateOverlay hands out the lowest free subnet, taking pools in the order
// they were configured and moving to the next when one is full.
//
// Address space belongs to the hub, not to whoever asks: two tenants picking
// their own prefixes would eventually pick the same one. Several pools exist
// so a hub can be given more room later without renumbering what it already
// handed out, and each carries its own instance size.
func allocateOverlay(pools []Pool, taken map[netip.Prefix]struct{}) (netip.Prefix, error) {
	if len(pools) == 0 {
		return netip.Prefix{}, fmt.Errorf("no overlay pool is configured")
	}

	for _, pool := range pools {
		if pool.Size < pool.Prefix.Bits() || pool.Size > pool.Prefix.Addr().BitLen() {
			return netip.Prefix{}, fmt.Errorf("instance size /%d does not fit in pool %s", pool.Size, pool.Prefix)
		}

		candidate := netip.PrefixFrom(pool.Prefix.Masked().Addr(), pool.Size)
		for pool.Prefix.Contains(candidate.Addr()) {
			if _, used := taken[candidate]; !used {
				return candidate, nil
			}

			next, ok := nextSubnet(candidate, pool.Size)
			if !ok {
				break
			}
			candidate = next
		}
	}

	return netip.Prefix{}, fmt.Errorf("every overlay pool is full: %s", poolList(pools))
}

func poolList(pools []Pool) string {
	parts := make([]string, 0, len(pools))
	for _, p := range pools {
		parts = append(parts, p.Prefix.String())
	}
	return strings.Join(parts, ", ")
}

// reserveLighthouse takes the first usable address of the prefix.
func reserveLighthouse(prefix netip.Prefix) (netip.Addr, error) {
	return lowestFree(prefix, nil)
}

// ParsePool reads a pool written as superprefix plus the size handed to each
// instance, for example 198.19.0.0/16/24: a /16 carved into /24s.
//
// The plain form 198.19.0.0/16 is accepted too and carves it into /24s, or
// into /112s for IPv6.
//
// /112 rather than /64: the /64 boundary exists for stateless autoconfiguration
// and neighbour discovery, and neither happens here - addresses come from a
// certificate onto a tun device. So an instance takes 16 bits of host, which is
// 65536 members written as a readable number, and leaves a /48 pool holding
// more instances than anybody will create. Being longer than /64 also means an
// instance's own prefix always wins longest prefix match against a /64 a
// connector carries.
func ParsePool(s string) (netip.Prefix, int, error) {
	s = strings.TrimSpace(s)

	last := strings.LastIndex(s, "/")
	if last < 0 {
		return netip.Prefix{}, 0, fmt.Errorf("pool %q has no prefix length", s)
	}

	if prefix, err := netip.ParsePrefix(s); err == nil {
		size := 24
		if prefix.Addr().Is6() {
			size = 112
		}
		if size < prefix.Bits() {
			size = prefix.Bits()
		}
		return prefix, size, nil
	}

	prefix, err := netip.ParsePrefix(s[:last])
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("pool %q is not <network>/<bits>/<size>", s)
	}

	size, err := strconv.Atoi(s[last+1:])
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("pool %q has a bad instance size: %w", s, err)
	}
	if size < prefix.Bits() || size > prefix.Addr().BitLen() {
		return netip.Prefix{}, 0, fmt.Errorf("instance size /%d does not fit in %s", size, prefix)
	}

	return prefix.Masked(), size, nil
}
