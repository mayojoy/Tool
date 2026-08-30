// Clash_rule.js v6.0
// 基于 kanwox/Clash-Rule v5.2 修改
// Rule Providers：blackmatrix7 / anti-ad.net / soffchen
// 支持 RULE_OPTIONS true/false 控制 Provider + RULE-SET 是否生成

function main(params) {
    if (!params || typeof params !== "object") params = {};
    if (!Array.isArray(params.proxies)) params.proxies = [];

    // ============================================================
    // 分流规则开关
    //
    // true  = 启用 Provider + RULE-SET
    // false = 不生成 Provider + 不生成 RULE-SET
    //
    // 以后主要修改这里即可
    // ============================================================
    const RULE_OPTIONS = {
        FCM: true,          // Google FCM 服务
        YouTube: true,      // YouTube 视频平台
        Google: true,       // Google 服务
        AI: true,           // 国外 AI 服务
        Microsoft: true,    // Microsoft 服务
        Apple: true,        // Apple 服务
        Telegram: true,     // Telegram 通讯软件
        Steam: true,        // Steam 游戏平台
        TikTok: true,       // TikTok 视频平台
        Twitter: true,      // Twitter 社交平台
        Instagram: true,    // Instagram 社交平台
        Netflix: true,      // Netflix 视频平台
        PikPak: true,       // PikPak 网盘服务
        Spotify: true,      // Spotify 音乐服务
        AdBlock: true,      // 广告拦截

        // 下面这些是你之前要求加入的规则
        BiliBili: true,     // 哔哩哔哩
        Bahamut: true,      // 巴哈姆特
        GlobalMedia: true,  // 国际媒体
        Github: true,       // GitHub
        Game: true          // 游戏
    };

    // ============================================================
    // 订阅是否使用 proxy-providers
    // ============================================================
    const subHasProviders =
        Object.keys(params["proxy-providers"] || {}).length > 0;

    // ============================================================
    // 基础配置
    // ============================================================
    const basicOptions = {
        "mixed-port": 7892,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "warning",
        "unified-delay": true,
        "tcp-concurrent": true,
        "ipv6": true,
        "find-process-mode": "off",

        "keep-alive-idle": 300,
        "keep-alive-interval": 30,

        "profile": {
            "store-selected": true,
            "store-fake-ip": true
        }
    };

    Object.assign(params, basicOptions);

    delete params["global-client-fingerprint"];

    // ============================================================
    // Sniffer
    // ============================================================
    params["sniffer"] = {
        "enable": true,
        "force-dns-mapping": true,
        "parse-pure-ip": true,
        "override-destination": true,

        "sniff": {
            "HTTP": {
                "ports": [80, "8080-8880"],
                "override-destination": true
            },

            "TLS": {
                "ports": [443, 8443]
            },

            "QUIC": {
                "ports": [443, 8443]
            }
        },

        "skip-domain": [
            "Mijia Cloud",
            "+.apple.com",
            "+.openai.com",
            "+.oaistatic.com",
            "+.oaiusercontent.com",
            "+.chatgpt.com"
        ]
    };

    // ============================================================
    // DNS
    // ============================================================
    const subDNS = params.dns || {};

    // 这里列出脚本实际生成的策略组
    const OWN_GROUPS = [
        "主代理",
        "静态",
        "直连",

        "AI",
        "Apple",
        "GitHub",
        "Google",
        "Microsoft",
        "Telegram",
        "TikTok",
        "TV",
        "Twitch",
        "X",
        "YouTube",

        "FCM",
        "Steam",
        "Instagram",
        "PikPak",
        "Spotify",
        "AdBlock",
        "哔哩哔哩",
        "国际媒体",
        "游戏平台"
    ];

    const BUILTIN_POLICIES = new Set([
        "DIRECT",
        "REJECT",
        "REJECT-DROP",
        "PASS",
        "GLOBAL"
    ]);

    const REGION_CODES = new Set([
        "HK",
        "JP",
        "KR",
        "SG",
        "TW",
        "US",
    ]);

    const refValid = ref =>
        BUILTIN_POLICIES.has(ref) ||
        OWN_GROUPS.indexOf(ref) !== -1 ||
        REGION_CODES.has(ref);

    const stripDanglingRef = entry => {
        const s = String(entry);
        const hash = s.indexOf("#");

        if (hash === -1) return s;

        const ref = s.slice(hash + 1)
            .split("&")[0]
            .trim();

        return refValid(ref)
            ? s
            : s.slice(0, hash);
    };

    const subPSN = []
        .concat(subDNS["proxy-server-nameserver"] || [])
        .map(stripDanglingRef);

    const subNS = []
        .concat(subDNS["nameserver"] || [])
        .map(stripDanglingRef);

    const subPolicy = Object.assign(
        {},
        subDNS["nameserver-policy"] || {}
    );

    const subFilter = []
        .concat(subDNS["fake-ip-filter"] || [])
        .filter(item =>
            !/^(rule-set|geosite):/i.test(String(item))
        );

    for (const k of Object.keys(subPolicy)) {
        if (k === "+." || k === "*" || k === "+") {
            delete subPolicy[k];
            continue;
        }

        if (/^(rule-set|geosite):/i.test(k)) {
            delete subPolicy[k];
            continue;
        }

        subPolicy[k] = []
            .concat(subPolicy[k])
            .map(stripDanglingRef);
    }

    // ============================================================
    // DNS 配置
    //
    // 注意：
    // 已经删除旧版本的
    // rule-set:cn-domain
    // rule-set:private-domain
    // rule-set:ads-domain
    //
    // 因为新版 Provider 不再使用这些名称。
    // ============================================================
    params["dns"] = {
        "enable": true,
        "listen": "127.0.0.1:1053",

        // DNS 层关闭 IPv6
        "ipv6": false,

        "prefer-h3": true,

        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-range6": "fdfe:dcba:9876::/64",

        "cache-algorithm": "arc",

        "use-hosts":
            subDNS["use-hosts"] !== undefined
                ? subDNS["use-hosts"]
                : true,

        "use-system-hosts":
            subDNS["use-system-hosts"] !== undefined
                ? subDNS["use-system-hosts"]
                : true,

        ...(subDNS.hosts
            ? { "hosts": subDNS.hosts }
            : {}),

        // ========================================================
        // Fake-IP 豁免
        // ========================================================
        "fake-ip-filter": [
            ...new Set([
                "+.lan",
                "+.local",

                "localhost.ptlogin2.qq.com",

                "+.msftconnecttest.com",
                "+.msftncsi.com",

                "+.ntp.org",

                "+.xboxlive.com",
                "+.playstation.net",
                "+.xbox.com",

                "xbox.ipv6.microsoft.com",

                "+.srv.nintendo.net",

                "time.windows.com",
                "time.apple.com",

                "+.stun.*",
                "+.stun.*.*",
                "+.stun.*.*.*",
                "+.stun.*.*.*.*",

                ...subFilter
            ])
        ],

        // ========================================================
        // 引导 DNS
        // ========================================================
        "default-nameserver": [
            "223.5.5.5",
            "119.29.29.29"
        ],

        // ========================================================
        // 节点域名解析
        // ========================================================
        "proxy-server-nameserver":
            subPSN.length > 0
                ? [...new Set(subPSN)]
                : [
                    "https://223.5.5.5/dns-query",
                    "https://doh.pub/dns-query"
                ],

        // ========================================================
        // 主 DNS
        // ========================================================
        "nameserver":
            subNS.length > 0
                ? [...new Set(subNS)]
                : [
                    "https://1.1.1.1/dns-query#主代理",
                    "https://8.8.8.8/dns-query#主代理"
                ],

        "nameserver-policy": subPolicy
    };

    // ============================================================
    // Rule Providers
    //
    // 固定：
    // Direct
    // Lan
    // Download
    // ChinaIP
    // ProxyLite
    //
    // 可选：
    // FCM
    // YouTube
    // Google
    // AI
    // Microsoft
    // Apple
    // Telegram
    // Steam
    // TikTok
    // Twitter
    // Instagram
    // Netflix
    // PikPak
    // Spotify
    // AdBlock
    // BiliBili
    // Bahamut
    // GlobalMedia
    // Github
    // Game
    // ============================================================

    const PROVIDERS = {

        // ========================================================
        // 固定规则
        // ========================================================

        "Direct": {
            "type": "http",
            "behavior": "domain",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Direct/Direct.yaml",
            "path": "./ruleset/Direct.yaml"
        },

        "Lan": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Lan/Lan.yaml",
            "path": "./ruleset/Lan.yaml"
        },

        "Download": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Download/Download.yaml",
            "path": "./ruleset/Download.yaml"
        },

        "ChinaMax_Domain": {
            "type": "http",
            "behavior": "domain",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml",
            "path": "./ruleset/ChinaMax_Domain.yaml"
        },

        "ChinaMax_IP": {
            "type": "http",
            "behavior": "ipcidr",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_IP.yaml",
            "path": "./ruleset/ChinaMax_IP.yaml"
        },

        "ChinaIP": {
            "type": "http",
            "behavior": "ipcidr",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/soffchen/GeoIP2-CN@release/clash-rule-provider.yml",
            "path": "./ruleset/ChinaIP.yaml"
        },

        "ProxyLite": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ProxyLite/ProxyLite.yaml",
            "path": "./ruleset/ProxyLite.yaml"
        },

        // ========================================================
        // Google FCM
        // ========================================================
        "FCM": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://testingcf.jsdelivr.net/gh/dler-io/Rules@main/Clash/Provider/Google%20FCM.yaml",
            "path": "./ruleset/FCM.yaml"
        },

        // ========================================================
        // YouTube
        // ========================================================
        "YouTube": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/YouTube/YouTube.yaml",
            "path": "./ruleset/YouTube.yaml"
        },

        // ========================================================
        // Google
        // ========================================================
        "Google": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Google/Google.yaml",
            "path": "./ruleset/Google.yaml"
        },

        // ========================================================
        // AI
        // ========================================================
        "AI": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml",
            "path": "./ruleset/AI.yaml"
        },

        // ========================================================
        // Microsoft
        // ========================================================
        "Microsoft": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Microsoft/Microsoft.yaml",
            "path": "./ruleset/Microsoft.yaml"
        },

        // ========================================================
        // Apple
        // ========================================================
        "Apple": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Apple/Apple_Classical.yaml",
            "path": "./ruleset/Apple.yaml"
        },

        // ========================================================
        // Telegram
        // ========================================================
        "Telegram": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Telegram/Telegram.yaml",
            "path": "./ruleset/Telegram.yaml"
        },

        // ========================================================
        // Steam
        // ========================================================
        "Steam": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Steam/Steam.yaml",
            "path": "./ruleset/Steam.yaml"
        },

        // ========================================================
        // TikTok
        // ========================================================
        "TikTok": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/TikTok/TikTok.yaml",
            "path": "./ruleset/TikTok.yaml"
        },

        // ========================================================
        // Twitter
        // ========================================================
        "Twitter": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Twitter/Twitter.yaml",
            "path": "./ruleset/Twitter.yaml"
        },

        // ========================================================
        // Instagram
        // ========================================================
        "Instagram": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Instagram/Instagram.yaml",
            "path": "./ruleset/Instagram.yaml"
        },

        // ========================================================
        // Netflix
        // ========================================================
        "Netflix": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Netflix/Netflix.yaml",
            "path": "./ruleset/Netflix.yaml"
        },

        // ========================================================
        // PikPak
        // ========================================================
        "PikPak": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/PikPak/PikPak.yaml",
            "path": "./ruleset/PikPak.yaml"
        },

        // ========================================================
        // Spotify
        // ========================================================
        "Spotify": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Spotify/Spotify.yaml",
            "path": "./ruleset/Spotify.yaml"
        },

        // ========================================================
        // 广告
        // ========================================================
        "AdBlock": {
            "type": "http",
            "behavior": "domain",
            "interval": 86400,
            "url":
                "https://anti-ad.net/clash.yaml",
            "path": "./ruleset/anti-ad-clash.yaml"
        },

        // ========================================================
        // 哔哩哔哩
        // ========================================================
        "BiliBili": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/BiliBili/BiliBili.yaml",
            "path": "./ruleset/BiliBili.yaml"
        },

        // ========================================================
        // Bahamut
        // ========================================================
        "Bahamut": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Bahamut/Bahamut.yaml",
            "path": "./ruleset/Bahamut.yaml"
        },

        // ========================================================
        // GlobalMedia
        // ========================================================
        "GlobalMedia": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/GlobalMedia/GlobalMedia_Classical.yaml",
            "path": "./ruleset/GlobalMedia.yaml"
        },

        // ========================================================
        // GitHub
        // ========================================================
        "Github": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/GitHub/GitHub.yaml",
            "path": "./ruleset/Github.yaml"
        },

        // ========================================================
        // Game
        // ========================================================
        "Game": {
            "type": "http",
            "behavior": "classical",
            "interval": 86400,
            "url":
                "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Game/Game.yaml",
            "path": "./ruleset/Game.yaml"
        }
    };

    // ============================================================
    // 创建 Rule Providers
    //
    // Direct / Lan / Download / ChinaIP / ProxyLite 永远启用
    //
    // 其它 Provider 根据 RULE_OPTIONS 控制
    // ============================================================
    params["rule-providers"] = {};

    const fixedProviders = [
        "Direct",
        "Lan",
        "Download",
        "ChinaIP",
        "ProxyLite"
    ];

    fixedProviders.forEach(name => {
        params["rule-providers"][name] = PROVIDERS[name];
    });

    Object.keys(RULE_OPTIONS).forEach(name => {
        if (
            RULE_OPTIONS[name] === true &&
            PROVIDERS[name]
        ) {
            params["rule-providers"][name] =
                PROVIDERS[name];
        }
    });

    // ============================================================
    // 节点参数优化
    // ============================================================
    const FP_OK = [
        "vless",
        "vmess",
        "trojan"
    ];

    (params.proxies || []).forEach(proxy => {
        if (!proxy) return;

        if (
            proxy.type !== "direct" &&
            !("ip-version" in proxy)
        ) {
            proxy["ip-version"] = "ipv4-prefer";
        }

        if (
            FP_OK.indexOf(proxy.type) !== -1 &&
            !proxy["client-fingerprint"]
        ) {
            const usesTLS =
                proxy.type === "trojan" ||
                proxy.tls === true ||
                proxy["reality-opts"];

            if (usesTLS) {
                proxy["client-fingerprint"] = "chrome";
            }
        }

        if (
            proxy["reality-opts"] &&
            !(
                "support-x25519mlkem768"
                in proxy["reality-opts"]
            )
        ) {
            proxy["reality-opts"]
                ["support-x25519mlkem768"] = true;
        }
    });

    // ============================================================
    // Proxy Provider 参数优化
    // ============================================================
    Object.values(
        params["proxy-providers"] || {}
    ).forEach(provider => {

        if (
            provider &&
            typeof provider === "object"
        ) {
            provider.override = Object.assign(
                {},
                provider.override || {},
                {
                    "ip-version": "ipv4-prefer",

                    "override-expr": [
                        ...(
                            (
                                provider.override || {}
                            )["override-expr"] || []
                        ),

                        '(select(.type == "trojan" or ((.type == "vless" or .type == "vmess") and (.tls == true or has("reality-opts")))) | select(has("client-fingerprint") | not) | .client-fingerprint) = "chrome"',

                        '(select(has("reality-opts")) | select(.reality-opts | has("support-x25519mlkem768") | not) | .reality-opts.support-x25519mlkem768) = true'
                    ]
                }
            );
        }
    });

    // ============================================================
    // 节点排除规则
    // ============================================================
    const excludeFilter =
        '(?i)(剩余|官网|套餐|流量|到期|过期|更新|刷新|订阅|群|网址|客服|欢迎|加入|Expire|Traffic|Reset|(^|[^A-Za-z0-9])(\\d+(\\.\\d+)?\\s*(GB|TB)|\\d+\\s*Days?)([^A-Za-z0-9]|$))';

    // ============================================================
    // 地区节点
    // ============================================================
    const regions = [
        {
            name: "HK",
            regex: "(?i)(香港|🇭🇰|(^|[^A-Za-z])HK([^A-Za-z]|$)|(^|[^A-Za-z])HKG([^A-Za-z]|$)|Hong[ -]?Kong)",
            icon: "https://testingcf.jsdelivr.net/gh/HatScripts/circle-flags@gh-pages/flags/hk.svg"
        },
        {
            name: "JP",
            regex: "(?i)(日本|东京|東京|大阪|🇯🇵|(^|[^A-Za-z])JP([^A-Za-z]|$)|(^|[^A-Za-z])JPN([^A-Za-z]|$)|Japan)",
            icon: "https://testingcf.jsdelivr.net/gh/HatScripts/circle-flags@gh-pages/flags/jp.svg"
        },

        {
            name: "KR",
            regex: "(?i)(韩国|韓国|南韩|南韓|首尔|首爾|🇰🇷|(^|[^A-Za-z])KR([^A-Za-z]|$)|(^|[^A-Za-z])KOR([^A-Za-z]|$)|Korea)",
            icon: "https://testingcf.jsdelivr.net/gh/HatScripts/circle-flags@gh-pages/flags/kr.svg"
        },
        {
            name: "SG",
            regex: "(?i)(新加坡|狮城|獅城|🇸🇬|(^|[^A-Za-z])SG([^A-Za-z]|$)|(^|[^A-Za-z])SGP([^A-Za-z]|$)|Singapore)",
            icon: "https://testingcf.jsdelivr.net/gh/HatScripts/circle-flags@gh-pages/flags/sg.svg"
        },
        {
            name: "US",
            regex: "(?i)(美国|美國|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|🇺🇸|(^|[^A-Za-z])US([^A-Za-z]|$)|(^|[^A-Za-z])USA([^A-Za-z]|$)|United[ -]?States)",
            icon: "https://testingcf.jsdelivr.net/gh/HatScripts/circle-flags@gh-pages/flags/us.svg"
        },
    ];

    // ============================================================
    // 正则转换
    // ============================================================
    const toJsRegex = goStyleRegex =>
        new RegExp(
            goStyleRegex.replace(/^\(\?i\)/, ""),
            "i"
        );

    const allProxies =
        (params.proxies || [])
            .filter(proxy =>
                proxy &&
                proxy.type !== "direct"
            );

    const excludeRe =
        toJsRegex(excludeFilter);

    const threshold = 2;

    const matchedRegions =
        regions.filter(region => {

            const regex =
                toJsRegex(region.regex);

            let count = 0;

            for (const proxy of allProxies) {

                if (
                    proxy &&
                    proxy.name &&
                    regex.test(proxy.name) &&
                    !excludeRe.test(proxy.name)
                ) {
                    count++;

                    if (count >= threshold) {
                        return true;
                    }
                }
            }

            return false;
        });

    // ============================================================
    // 如果订阅本身使用 proxy-providers
    // 无法在脚本阶段知道具体节点
    // 所以保留全部地区组
    // ============================================================
    const activeRegions =
        subHasProviders
            ? regions
            : matchedRegions;

    const hasActiveRegions =
        activeRegions.length > 0;

    // ============================================================
    // 策略组
    // ============================================================
    let groups = [];

    // ============================================================
    // 主代理
    // ============================================================
    groups.push({
        name: "主代理",
        type: "select",

        icon:
            "https://testingcf.jsdelivr.net/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Proxy.png",

        proxies:
            hasActiveRegions
                ? [
                    ...activeRegions.map(
                        region => `${region.name}`
                    ),
                    "静态",
                    "直连"
                ]
                : [
                    "静态",
                    "直连"
                ]
    });

    // ============================================================
    // 静态
    // ============================================================
    groups.push({
        name: "静态",
        type: "select",

        icon:
            "https://testingcf.jsdelivr.net/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Static.png",

        "include-all": true,
        "exclude-type": "direct",
        "exclude-filter": excludeFilter,

        "empty-fallback": "REJECT"
    });

    // ============================================================
    // 直连
    // ============================================================
    groups.push({
        name: "直连",
        type: "select",
        hidden: true,

        icon:
            "https://testingcf.jsdelivr.net/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Direct.png",

        proxies: [
            "DIRECT"
        ],

        url:
            "http://connect.rom.miui.com/generate_204"
    });

    // ============================================================
    // App 策略组
    // ============================================================
    const appProxiesList = [
        "主代理",
        "直连",
        ...activeRegions.map(
            region => `${region.name}`
        )
    ];

    const apps = [
        {
            name: "AI",
            icon: "openai.png"
        },

        {
            name: "Apple",
            icon: "apple.png"
        },

        {
            name: "GitHub",
            icon:
                "https://i.postimg.cc/vTSTYrLQ/github.png"
        },

        {
            name: "Google",
            icon: "google.png"
        },

        {
            name: "Microsoft",
            icon: "microsoft.png"
        },

        {
            name: "Telegram",
            icon: "telegram.png"
        },

        {
            name: "TikTok",
            icon: "tiktok.png"
        },

        {
            name: "TV",
            icon: "netflix.png"
        },

        {
            name: "Twitch",
            icon: "twitch.png"
        },

        {
            name: "X",
            icon: "x.png"
        },

        {
            name: "YouTube",
            icon: "youtube.png"
        },

        {
            name: "FCM",
            icon: "google.png"
        },

        {
            name: "Steam",
            icon: "steam.png"
        },

        {
            name: "Instagram",
            icon: "instagram.png"
        },

        {
            name: "PikPak",
            icon: "pikpak.png"
        },

        {
            name: "Spotify",
            icon: "spotify.png"
        },

        {
            name: "AdBlock",
            icon: "adblock.png"
        },

        {
            name: "哔哩哔哩",
            icon: "bilibili.png"
        },

        {
            name: "国际媒体",
            icon: "netflix.png"
        },

        {
            name: "游戏平台",
            icon: "game.png"
        }
    ];

    // ============================================================
    // 根据开关决定是否生成策略组
    // ============================================================
    const enabledApps = new Set([
        "AI",
        "Apple",
        "Google",
        "Microsoft",
        "Telegram",
        "TikTok",
        "TV",
        "X",
        "YouTube",
        "FCM",
        "Steam",
        "Instagram",
        "PikPak",
        "Spotify",
        "AdBlock",
        "哔哩哔哩",
        "国际媒体",
        "游戏平台"
    ]);

    if (RULE_OPTIONS.Github === true) {
        enabledApps.add("GitHub");
    }

    if (RULE_OPTIONS.Twitch === true) {
        enabledApps.add("Twitch");
    }

    apps.forEach(app => {

        let enabled = true;

        if (app.name === "AI") {
            enabled = RULE_OPTIONS.AI === true;
        }

        if (app.name === "Apple") {
            enabled = RULE_OPTIONS.Apple === true;
        }

        if (app.name === "GitHub") {
            enabled = RULE_OPTIONS.Github === true;
        }

        if (app.name === "Google") {
            enabled = RULE_OPTIONS.Google === true;
        }

        if (app.name === "Microsoft") {
            enabled = RULE_OPTIONS.Microsoft === true;
        }

        if (app.name === "Telegram") {
            enabled = RULE_OPTIONS.Telegram === true;
        }

        if (app.name === "TikTok") {
            enabled = RULE_OPTIONS.TikTok === true;
        }

        if (app.name === "TV") {
            enabled = RULE_OPTIONS.Netflix === true;
        }

        if (app.name === "YouTube") {
            enabled = RULE_OPTIONS.YouTube === true;
        }

        if (app.name === "FCM") {
            enabled = RULE_OPTIONS.FCM === true;
        }

        if (app.name === "Steam") {
            enabled = RULE_OPTIONS.Steam === true;
        }

        if (app.name === "Instagram") {
            enabled = RULE_OPTIONS.Instagram === true;
        }

        if (app.name === "PikPak") {
            enabled = RULE_OPTIONS.PikPak === true;
        }

        if (app.name === "Spotify") {
            enabled = RULE_OPTIONS.Spotify === true;
        }

        if (app.name === "AdBlock") {
            enabled = RULE_OPTIONS.AdBlock === true;
        }

        if (app.name === "哔哩哔哩") {
            enabled =
                RULE_OPTIONS.BiliBili === true ||
                RULE_OPTIONS.Bahamut === true;
        }

        if (app.name === "国际媒体") {
            enabled =
                RULE_OPTIONS.GlobalMedia === true ||
                RULE_OPTIONS.Netflix === true;
        }

        if (app.name === "游戏平台") {
            enabled =
                RULE_OPTIONS.Game === true ||
                RULE_OPTIONS.Steam === true;
        }

        if (!enabled) return;

        const icon =
            app.icon.startsWith("http")
                ? app.icon
                : `https://testingcf.jsdelivr.net/gh/shindgew/WHATSINStash@main/icon/${app.icon}`;

        groups.push({
            name: app.name,
            type: "select",
            icon: icon,
            proxies: appProxiesList,

            "include-all": true,
            "exclude-type": "direct",
            "exclude-filter": excludeFilter
        });
    });

    // ============================================================
    // 国家测速组
    // ============================================================
    activeRegions.forEach(region => {

        groups.push({
            name: `${region.name}`,
            type: "url-test",
            hidden: true,

            icon: region.icon,

            "include-all": true,
            "exclude-type": "direct",

            "filter": region.regex,
            "exclude-filter": excludeFilter,

            "empty-fallback": "REJECT",

            "url":
                "https://www.gstatic.com/generate_204",

            "interval": 300,
            "tolerance": 30,

            "lazy": true,

            "timeout": 5000,
            "max-failed-times": 5,

            "expected-status": 204
        });
    });

    params["proxy-groups"] = groups;

    // ============================================================
    // 分流规则
    //
    // 顺序非常重要：
    // Direct / Lan / Download
    // ↓
    // AdBlock
    // ↓
    // 各服务
    // ↓
    // ChinaIP
    // ↓
    // GEOIP CN
    // ↓
    // 主代理
    // ============================================================
    const rules = [];

    // ============================================================
    // 固定规则
    // ============================================================
    rules.push(
        "RULE-SET,Direct,DIRECT",
        "RULE-SET,Lan,DIRECT",
        "RULE-SET,Download,DIRECT"
    );

    // ============================================================
    // AdBlock
    // ============================================================
    if (RULE_OPTIONS.AdBlock === true) {
        rules.push(
            "RULE-SET,AdBlock,REJECT"
        );
    }

    // ============================================================
    // FCM
    // ============================================================
    if (RULE_OPTIONS.FCM === true) {
        rules.push(
            "RULE-SET,FCM,FCM"
        );
    }

    // ============================================================
    // AI
    // ============================================================
    if (RULE_OPTIONS.AI === true) {
        rules.push(
            "RULE-SET,AI,AI"
        );
    }

    // ============================================================
    // YouTube
    // ============================================================
    if (RULE_OPTIONS.YouTube === true) {
        rules.push(
            "RULE-SET,YouTube,YouTube"
        );
    }

    // ============================================================
    // Google
    // ============================================================
    if (RULE_OPTIONS.Google === true) {
        rules.push(
            "RULE-SET,Google,Google"
        );
    }

    // ============================================================
    // Microsoft
    // ============================================================
    if (RULE_OPTIONS.Microsoft === true) {
        rules.push(
            "RULE-SET,Microsoft,Microsoft"
        );
    }

    // ============================================================
    // Apple
    // ============================================================
    if (RULE_OPTIONS.Apple === true) {
        rules.push(
            "RULE-SET,Apple,Apple"
        );
    }

    // ============================================================
    // Telegram
    // ============================================================
    if (RULE_OPTIONS.Telegram === true) {
        rules.push(
            "RULE-SET,Telegram,Telegram"
        );
    }

    // ============================================================
    // Steam
    // ============================================================
    if (RULE_OPTIONS.Steam === true) {
        rules.push(
            "RULE-SET,Steam,游戏平台"
        );
    }

    // ============================================================
    // TikTok
    // ============================================================
    if (RULE_OPTIONS.TikTok === true) {
        rules.push(
            "RULE-SET,TikTok,TikTok"
        );
    }

    // ============================================================
    // Twitter
    // ============================================================
    if (RULE_OPTIONS.Twitter === true) {
        rules.push(
            "RULE-SET,Twitter,X"
        );
    }

    // ============================================================
    // Instagram
    // ============================================================
    if (RULE_OPTIONS.Instagram === true) {
        rules.push(
            "RULE-SET,Instagram,Instagram"
        );
    }

    // ============================================================
    // Netflix
    // ============================================================
    if (RULE_OPTIONS.Netflix === true) {
        rules.push(
            "RULE-SET,Netflix,TV"
        );
    }

    // ============================================================
    // PikPak
    // ============================================================
    if (RULE_OPTIONS.PikPak === true) {
        rules.push(
            "RULE-SET,PikPak,PikPak"
        );
    }

    // ============================================================
    // Spotify
    // ============================================================
    if (RULE_OPTIONS.Spotify === true) {
        rules.push(
            "RULE-SET,Spotify,Spotify"
        );
    }

    // ============================================================
    // BiliBili
    // ============================================================
    if (RULE_OPTIONS.BiliBili === true) {
        rules.push(
            "RULE-SET,BiliBili,哔哩哔哩"
        );
    }

    // ============================================================
    // Bahamut
    // ============================================================
    if (RULE_OPTIONS.Bahamut === true) {
        rules.push(
            "RULE-SET,Bahamut,哔哩哔哩"
        );
    }

    // ============================================================
    // GlobalMedia
    // ============================================================
    if (RULE_OPTIONS.GlobalMedia === true) {
        rules.push(
            "RULE-SET,GlobalMedia,国际媒体"
        );
    }

    // ============================================================
    // GitHub
    // ============================================================
    if (RULE_OPTIONS.Github === true) {
        rules.push(
            "RULE-SET,Github,GitHub"
        );
    }

    // ============================================================
    // Game
    // ============================================================
    if (RULE_OPTIONS.Game === true) {
        rules.push(
            "RULE-SET,Game,游戏平台"
        );
    }

    // ============================================================
    // ProxyLite
    // ============================================================
    rules.push(
        "RULE-SET,ProxyLite,主代理"
    );

    // ============================================================
    // 中国 IP
    // ============================================================
    rules.push(
        "RULE-SET,ChinaMax_Domain,DIRECT",
        "RULE-SET,ChinaMax_IP,DIRECT,no-resolve"
        "RULE-SET,ChinaIP,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT"
        
    );

    // ============================================================
    // 最终兜底
    // ============================================================
    rules.push(
        "MATCH,主代理"
    );

    params["rules"] = rules;

    return params;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
