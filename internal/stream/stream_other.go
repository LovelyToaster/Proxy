//go:build !linux

package stream

func trySplice(dst, src Conn, touch func()) (bool, error) {
	return false, nil
}
