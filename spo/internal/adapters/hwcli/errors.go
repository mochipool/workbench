package hwcli

import "errors"

// Typed failures of the hardware signer. They replace the `exit 1` of every
// upstream failure path (spec: SPO-Chw-INV-002) with errors a caller can test.
var (
	// ErrToolUnavailable: cardano-hw-cli is not in the release set, is not
	// executable, or failed its version gate (SPO-Chw-PRE-001, SPO-Chw-PRE-002).
	ErrToolUnavailable = errors.New("cardano-hw-cli is not available")
	// ErrNoDevice: no device with the Cardano app open answered within the
	// wait. Upstream waits for ever (SPO-Chw-PR-001); the port is bounded.
	ErrNoDevice = errors.New("no hardware wallet answered: connect and unlock your device and open the Cardano app")
	// ErrUnreadableVersion: the device answer has no readable app or firmware
	// version. Upstream lets an unreadable version pass (SPO-Chw-INV-001); here it fails.
	ErrUnreadableVersion = errors.New("the hardware wallet's app or firmware version is unreadable")
	// ErrUnsupportedVendor: the device is none of Ledger, Trezor and Keystone
	// (SPO-Chw-PRE-005).
	ErrUnsupportedVendor = errors.New("unsupported hardware wallet vendor")
	// ErrDeviceTooOld: the app or firmware version is below the minimum for its
	// vendor (SPO-Chw-PRE-004).
	ErrDeviceTooOld = errors.New("the hardware wallet's app or firmware is too old")
	// ErrNotSupported: the device's profile does not offer the operation or the
	// role's key (the vendor restriction of SPO-Chw-PRE-003, the table of
	// custody.HardwareTable).
	ErrNotSupported = errors.New("the hardware wallet cannot do this")
	// ErrRejected: the user declined on the device (SPO-Ptx-PRE-005).
	ErrRejected = errors.New("the action was rejected on the hardware wallet")
	// ErrDisconnected: the device went away during the action (SPO-Ptx-PRE-005).
	ErrDisconnected = errors.New("the hardware wallet disconnected")
	// ErrDeviceError: the tool reported ERROR (SPO-Ptx-PRE-005, SPO-Ctx-PRE-004).
	ErrDeviceError = errors.New("cardano-hw-cli reported an error")
	// ErrExpertModeRequired: the device refused for a security reason; enable
	// expert mode on the device and allow unrestricted mode (SPO-21b-PRE-009).
	ErrExpertModeRequired = errors.New("the hardware wallet needs expert mode to sign this transaction: enable it on the device and allow unrestricted mode")
	// ErrToolFailed: the tool exited non-zero with no recognised message.
	ErrToolFailed = errors.New("cardano-hw-cli failed")
	// ErrBadDeviceOutput: a file the tool wrote is not the shape the adapter
	// expects, or does not verify.
	ErrBadDeviceOutput = errors.New("cardano-hw-cli wrote an unexpected result")
	// ErrBadNetwork: the configuration names no network, or two.
	ErrBadNetwork = errors.New("the hardware signer needs exactly one of mainnet or a testnet magic")
	// ErrNoSigningFiles: the signer has no source of hardware signing files.
	ErrNoSigningFiles = errors.New("no hardware signing files are available")
)
