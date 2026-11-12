package windivert

type Status struct {
	Backend      string `json:"backend"`
	DLL          string `json:"dll,omitempty"`
	DriverLoaded bool   `json:"driver_loaded"`
	Version      string `json:"version,omitempty"`
}

type Counts struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	IPv4    uint64 `json:"ipv4"`
	IPv6    uint64 `json:"ipv6"`
}
