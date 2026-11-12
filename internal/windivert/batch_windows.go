package windivert

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

func (g *Capture) sendBatch(data []byte, addresses [][10]uint64) error {
	g.io.RLock()
	defer g.io.RUnlock()
	var sent uint32
	ok, _, err := g.lib.sendEx.Call(g.handle, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&sent)), 0, uintptr(unsafe.Pointer(&addresses[0])), uintptr(len(addresses)*80), 0)
	runtime.KeepAlive(data)
	runtime.KeepAlive(addresses)
	if ok == 0 {
		return fmt.Errorf("WinDivertSendEx: %w", err)
	}
	if sent != uint32(len(data)) {
		return errors.New("short WinDivert batch send")
	}
	g.sentBatches.Add(1)
	g.sentPackets.Add(uint64(len(addresses)))
	return nil
}
