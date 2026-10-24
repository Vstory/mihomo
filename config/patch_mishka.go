//go:build mishka

package config

import (
	C "github.com/metacubex/mihomo/constant"
)

var (
	mishkaDefaultNameServers = []string{
		"223.5.5.5",
		"119.29.29.29",
		"8.8.4.4",
		"1.0.0.1",
	}
	mishkaDefaultFakeIPFilter = []string{
		// STUN
		"+.stun.*.*",
		"+.stun.*.*.*",
		"+.stun.*.*.*.*",
		"+.stun.*.*.*.*.*",
		// Google Voices
		"lens.l.google.com",
		// Nintendo Switch STUN
		"*.n.n.srv.nintendo.net",
		// PlayStation STUN
		"+.stun.playstation.net",
		// Xbox
		"xbox.*.*.microsoft.com",
		"*.*.xboxlive.com",
		// Microsoft Captive Portal
		"*.msftncsi.com",
		"*.msftconnecttest.com",
		// Bilibili CDN
		"*.mcdn.bilivideo.cn",
		// Windows default LAN workgroup
		"WORKGROUP",
	}
	mishkaDefaultFakeIPRange = "28.0.0.0/8"
	// DefaultRawConfig 内置的 external-ui-url 默认值；用于判断「用户没有显式指定下载地址」。
	mishkaStockExternalUIURL = "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
	// 替换用的下载源：zashboard 经 gh-proxy 镜像（与作者 mihomo_box 自带配置同源）。
	// 内置默认直连 github.com，国内网络基本不可达，会导致 UI 下载失败、面板空白。
	mishkaDefaultExternalUIURL = "https://v6.gh-proxy.org/https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages-no-fonts.zip"
)

func init() {
	mishkaPatch = patchMishka
}

// patchMishka adjusts the parsed RawConfig for Android usage:
//   - When the subscription has DNS disabled, inject a sensible default
//     (fake-ip mode, a mix of domestic and international nameservers, and a
//     fake-ip filter list covering STUN, game consoles, captive portals, etc.).
//     Applies to all tunnel modes (VPN / ROOT TUN / ROOT TPROXY) because dns
//     hijack/redirect leaves no responder when DNS is off.
//   - In VPN mode only (FileDescriptor > 0): when AppendSystemDNS is set
//     (either by the subscription or implied by the default injection above),
//     append "system://" so Android system DNS acts as a last-resort fallback.
//     Skipped under ROOT modes — ROOT TUN would re-enter sing-tun's catch-all
//     route and loop, and ROOT TPROXY has no Kotlin-side UpdateSystemDNS feed
//     either, so the entry would be a dead nameserver slot.
//   - When running in VPN mode (FileDescriptor > 0), rebuild cfg.Tun with a
//     whitelist of fields required by sing-tun's fd path, dropping any
//     subscription-supplied Linux-only fields that would otherwise crash
//     sing-tun on Android (auto-redirect, iproute2-*, include-uid,
//     include-interface, route-address, etc.).
//   - When neither external-ui nor external-ui-name is configured, inject
//     external-ui: "ui" (plus a gh-proxy mirrored download URL if the stock
//     default is still in place) so the in-app external panel WebView has
//     something to serve at /ui instead of a bare 404.
func patchMishka(cfg *RawConfig) {
	if !cfg.DNS.Enable {
		cfg.DNS = DefaultRawConfig().DNS
		cfg.DNS.Enable = true
		cfg.DNS.NameServer = mishkaDefaultNameServers
		cfg.DNS.EnhancedMode = C.DNSFakeIP
		cfg.DNS.FakeIPRange = mishkaDefaultFakeIPRange
		cfg.DNS.FakeIPFilter = mishkaDefaultFakeIPFilter
		if cfg.Tun.FileDescriptor > 0 {
			cfg.ClashForAndroid.AppendSystemDNS = true
		}
	}
	if cfg.Tun.FileDescriptor > 0 && cfg.ClashForAndroid.AppendSystemDNS {
		cfg.DNS.NameServer = append(cfg.DNS.NameServer, "system://")
	}

	// ROOT 模式（fd == 0）走 mihomo TUN（netlink + tun.New()）路径。
	if cfg.Tun.FileDescriptor > 0 {
		// 白名单外的所有 RawTun 字段归零。
		cfg.Tun = RawTun{
			Enable:              cfg.Tun.Enable,
			Device:              cfg.Tun.Device,
			Stack:               cfg.Tun.Stack,
			DNSHijack:           cfg.Tun.DNSHijack,
			AutoRoute:           cfg.Tun.AutoRoute,
			AutoDetectInterface: cfg.Tun.AutoDetectInterface,
			Inet6Address:        cfg.Tun.Inet6Address,
			MTU:                 cfg.Tun.MTU,
			FileDescriptor:      cfg.Tun.FileDescriptor,
			IncludePackage:      cfg.Tun.IncludePackage,
			ExcludePackage:      cfg.Tun.ExcludePackage,
		}
	}

	// 外置面板兜底：应用内 WebView 打开 /ui 路由，而 mihomo 只有在 external-ui 非空时才
	// 挂载该路由（否则 404 → 面板空白）。大量订阅配置不带这个字段，这里注入默认 "ui"
	// （配置目录下的相对路径，能过 IsSafePath 检查）：ui/ 目录已有内容则直接伺服；
	// 为空则 AutoDownloadUI 启动时自动下载一次，失败仅记日志、不影响内核运行。
	// 用户显式配置过 external-ui 或 external-ui-name 时完全尊重原配置，不做任何改动。
	if cfg.ExternalUI == "" && cfg.ExternalUIName == "" {
		cfg.ExternalUI = "ui"
		// 下载地址仅替换「还是内置默认值」的情况；订阅自带 external-ui-url 则保留。
		if cfg.ExternalUIURL == "" || cfg.ExternalUIURL == mishkaStockExternalUIURL {
			cfg.ExternalUIURL = mishkaDefaultExternalUIURL
		}
	}
}
