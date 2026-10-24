//go:build android && (!cmfa || mishka)

package sing_tun

import (
	"errors"
	"sync"

	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing-tun"
)

type packageManagerCallback struct{}

func (cb *packageManagerCallback) OnPackagesUpdated(packageCount int, sharedCount int) {}

func newPackageManager() (tun.PackageManager, error) {
	packageManager, err := tun.NewPackageManager(tun.PackageManagerOptions{
		Callback: &packageManagerCallback{},
		Logger:   log.SingLogger,
	})
	if err != nil {
		return nil, err
	}
	err = packageManager.Start()
	if err != nil {
		return nil, err
	}
	return packageManager, nil
}

var (
	globalPM tun.PackageManager
	pmOnce   sync.Once
	pmErr    error
)

func getPackageManager() (tun.PackageManager, error) {
	pmOnce.Do(func() {
		globalPM, pmErr = newPackageManager()
	})
	return globalPM, pmErr
}

// GetPackageManager returns the shared Android package manager, initializing
// it on first use. Used by other inbounds (e.g. the eBPF inbound) to resolve
// include/exclude package names to UIDs.
func GetPackageManager() (tun.PackageManager, error) {
	return getPackageManager()
}

func (l *Listener) buildAndroidRules(tunOptions *tun.Options) error {
	// TUN handed in as an fd (Android VpnService) already has its routes set up by the Kotlin
	// side, so sing-tun must not build them again; package filtering is done by the VPN builder.
	if tunOptions.FileDescriptor > 0 {
		return nil
	}
	if len(tunOptions.IncludePackage) == 0 && len(tunOptions.ExcludePackage) == 0 {
		return nil
	}
	packageManager, err := getPackageManager()
	if err != nil {
		return err
	}
	tunOptions.BuildAndroidRules(packageManager, l.handler)
	return nil
}

func findPackageName(metadata *constant.Metadata) (string, error) {
	packageManager, err := getPackageManager()
	if err != nil {
		return "", err
	}
	uid := metadata.Uid
	if sharedPackage, loaded := packageManager.SharedPackageByID(uid % 100000); loaded {
		return sharedPackage, nil
	}
	if packageName, loaded := packageManager.PackageByID(uid % 100000); loaded {
		return packageName, nil
	}
	return "", errors.New("package not found")
}

func init() {
	// Mishka always wants the uid -> package-name resolver: rules match on process names and
	// the app does not use CMFA's package-name injection, which is why features.CMFA used to
	// gate this off under the cmfa build tag.
	process.DefaultPackageNameResolver = findPackageName
}
