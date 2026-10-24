//go:build mishka

package config

import (
	"slices"

	C "github.com/metacubex/mihomo/constant"
)

// DefaultRawConfig 的 DNS 全部留空，缺 dns: 段的精简订阅在 TUN dns-hijack 下无法解析任何域名。
// 对齐 CMFA patchAndroidConfig 的兜底逻辑（由 --tags mishka 独立承载，避免引入 cmfa tag 对
// component/dialer 等处的副作用）：当用户与订阅都未开启 DNS 时，注入默认公网 DoH + fake-ip。
var mishkaDefaultNameServers = []string{
	"223.5.5.5",
	"119.29.29.29",
	"https://223.5.5.5/dns-query",
	"https://120.53.53.53/dns-query",
}

const mishkaDefaultFakeIPRange = "198.18.0.1/16"

var mishkaDefaultFakeIPFilter = []string{
	"*.lan",
	"*.local",
	"time.*.com",
	"ntp.*.com",
	"+.market.xiaomi.com",
	"localhost.ptlogin2.qq.com",
	"+.msftncsi.com",
	"www.msftconnecttest.com",
}

// DefaultRawConfig 把 ExternalUIURL 硬编码为 MetaCubeX/metacubexd 的原版地址（见 config.go），
// 订阅未写 external-ui-url 时 rawCfg 里也已经有这个非空值；用同一常量识别「未由订阅显式指定」。
const (
	mishkaStockExternalUIURL   = "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
	mishkaDefaultExternalUIURL = "https://github.com/jieluojun/metacubexd/archive/refs/heads/gh-pages.zip"
)

func patchMishka(cfg *RawConfig) {
	if !cfg.DNS.Enable {
		cfg.DNS = DefaultRawConfig().DNS
		cfg.DNS.Enable = true
		cfg.DNS.NameServer = mishkaDefaultNameServers
		cfg.DNS.EnhancedMode = C.DNSFakeIP
		cfg.DNS.FakeIPRange = mishkaDefaultFakeIPRange
		cfg.DNS.FakeIPFilter = mishkaDefaultFakeIPFilter
		cfg.ClashForAndroid.AppendSystemDNS = true
	}
	if cfg.ClashForAndroid.AppendSystemDNS && !slices.Contains(cfg.DNS.NameServer, "system://") && !slices.Contains(cfg.DNS.NameServer, "system") {
		cfg.DNS.NameServer = append(cfg.DNS.NameServer, "system://")
	}

	// ROOT 模式（fd == 0）走 mihomo TUN（netlink + tun.New()）路径。
	if cfg.Tun.FileDescriptor > 0 {
		cfg.Interface = ""
		cfg.RoutingMark = 0
		cfg.ExternalControllerTLS = ""
		cfg.Listeners = slices.DeleteFunc(cfg.Listeners, func(mapping map[string]any) bool {
			switch mapping["type"] {
			case "tun", "tproxy", "redir":
				return true
			default:
				return false
			}
		})
		// 白名单外的所有 RawTun 字段归零（包括 CongestionController）。
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
		}
	}

	// 未配置 external-ui 时给一个默认静态目录与下载源，避免用户进 Web 面板看到 404。
	// 订阅或覆写显式写了 external-ui / external-ui-name / 自定义 external-ui-url 时完全不动。
	if cfg.ExternalUI == "" && cfg.ExternalUIName == "" {
		cfg.ExternalUI = "ui"
		// 下载地址仅替换「还是内置默认值」的情况；订阅自带 external-ui-url 则保留。
		if cfg.ExternalUIURL == "" || cfg.ExternalUIURL == mishkaStockExternalUIURL {
			cfg.ExternalUIURL = mishkaDefaultExternalUIURL
		}
	}
}
