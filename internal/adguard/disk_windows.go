//go:build windows

package adguard

func availableDiskMB(_ string) (uint64, error) {
	return 10240, nil
}
