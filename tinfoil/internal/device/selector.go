package device

// Selector is a fixed topology identity, not an enumerated /dev name.
type Selector struct {
	PCIAddress string
	Serial     string
	Partition  int
}

func PackSelector(index int, encrypted bool) (Selector, error) {
	address, err := modelDiskPCIAddress(index)
	if err != nil {
		return Selector{}, err
	}
	s := Selector{PCIAddress: address, Serial: modelDiskSerial(index)}
	if encrypted {
		s.Partition = EMWPPayloadPartition
	}
	return s, nil
}

func DiskSelector(packCount, index int) (Selector, error) {
	address, err := storageDiskPCIAddress(packCount, index)
	if err != nil {
		return Selector{}, err
	}
	return Selector{PCIAddress: address, Serial: storageDiskSerial(index)}, nil
}

// Resolve checks the controller and serial each time the volume is activated.
func (s Selector) Resolve() (string, error) {
	return waitForDevice(func() (string, error) {
		disk, err := findDiskByPCIAddress(s.PCIAddress, s.Serial)
		if err != nil {
			return "", err
		}
		if s.Partition != 0 {
			return findPartition(disk, s.Partition)
		}
		return disk, nil
	})
}
