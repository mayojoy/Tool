```javascript
/**
 * Clash / Mihomo JS 覆写脚本
 *
 * 用途：
 *   根据 ruleOptionsEnable 自动控制策略组及相关配置
 *
 * 适用于：
 *   Mihomo / Clash Meta Script
 *
 * true  = 启用
 * false = 禁用
 */

// ============================================================
// 自定义配置选项
// ============================================================

const ruleOptionsEnable = {

  // ----------------------------------------------------------
  // 基础策略组
  // ----------------------------------------------------------

  手动选择: false,       // 是否启用手动选择策略组
  自动选择: false,       // 是否启用自动选择策略组
  负载均衡: false,       // 是否启用负载均衡策略组


  // ----------------------------------------------------------
  // 分流策略配置
  // ----------------------------------------------------------

  AI: true,              // 国外 AI 服务
  Media: true,           // 国外视频平台
  FCM: false,            // Google FCM 服务
  Google: true,          // Google 服务
  Microsoft: true,       // Microsoft 服务
  Apple: true,           // Apple 服务
  Telegram: true,        // Telegram
  Steam: true,           // Steam
  TikTok: true,          // TikTok
  Twitter: true,         // Twitter
  Emby: false,           // Emby
  PikPak: true,          // PikPak
  Spotify: true,         // Spotify
  Crypto: false,         // 加密货币
  EHentai: false,        // E-Hentai
  AdBlock: true,         // 广告拦截


  // ----------------------------------------------------------
  // 非分流策略配置
  // ----------------------------------------------------------

  生成地区自动选择组: true,    // 生成地区自动选择策略组
  隐藏地区手动选择组: false,   // 隐藏地区手动选择策略组
  生成倍率组: false,            // 生成低倍率 / 高倍率策略组

  分流组添加所有节点: false,    // 分流组是否添加所有节点
  过滤高倍率节点: false,        // 是否过滤高倍率节点
  过滤非地区节点: true,         // 是否过滤非地区节点

  屏蔽国外QUIC: true,           // 屏蔽国外 QUIC
};


// ============================================================
// 基础工具函数
// ============================================================

function enabled(name) {
  return ruleOptionsEnable[name] === true;
}


/**
 * 安全获取对象
 */
function getObject(config, key, fallback) {
  if (!config[key]) {
    config[key] = fallback;
  }

  return config[key];
}


/**
 * 判断节点名称是否属于指定地区
 */
function isRegionProxy(name, region) {

  const patterns = {

    HK: /香港|港深|深港|沪港|广港|陆港|(?<![a-zA-Z])hk(?![a-zA-Z])|hkg|hongkong|hong kong|🇭🇰/i,

    TW: /台湾|台灣|新北|台北|高雄|(?<![a-zA-Z])tw(?![a-zA-Z])|tpe|taiwan|🇹🇼/i,

    JP: /日本|东京|東京|大阪|大阪|埼玉|(?<![a-zA-Z])jp(?![a-zA-Z])|jpn|japan|🇯🇵/i,

    SG: /新加坡|狮城|獅城|(?<![a-zA-Z])sg(?![a-zA-Z])|sgp|singapore|🇸🇬/i,

    US: /美国|美國|纽约|紐約|洛杉矶|洛杉磯|西雅图|西雅圖|(?<![a-zA-Z])us(?![a-zA-Z])|usa|united states|🇺🇸/i,

    KR: /韩国|韓國|首尔|首爾|釜山|(?<![a-zA-Z])kr(?![a-zA-Z])|kor|korea|🇰🇷/i,

    GB: /英国|英國|伦敦|倫敦|(?<![a-zA-Z])uk(?![a-zA-Z])|gbr|england|🇬🇧/i,

    DE: /德国|德國|柏林|法兰克福|法蘭克福|(?<![a-zA-Z])de(?![a-zA-Z])|germany|🇩🇪/i,

    FR: /法国|法國|巴黎|(?<![a-zA-Z])fr(?![a-zA-Z])|france|🇫🇷/i,

    CN: /中国|中國|大陆|大陸|内地|內地|上海|北京|广州|廣州|深圳|杭州|🇨🇳/i
  };

  return patterns[region] ? patterns[region].test(name) : false;
}


/**
 * 获取地区节点
 */
function getRegionNodes(proxies, region) {

  return proxies
    .filter(proxy => {

      const name = proxy.name || "";

      // 过滤非地区节点
      if (enabled("过滤非地区节点")) {
        return isRegionProxy(name, region);
      }

      return isRegionProxy(name, region);
    })
    .map(proxy => proxy.name);
}


/**
 * 删除重复项目
 */
function unique(array) {
  return [...new Set(array)];
}


/**
 * 删除不存在的节点
 */
function validProxies(list, proxyNames) {

  return unique(
    list.filter(name => proxyNames.includes(name))
  );
}


// ============================================================
// 节点过滤
// ============================================================

function filterProxies(proxies) {

  return proxies.filter(proxy => {

    const name = proxy.name || "";


    // --------------------------------------------------------
    // 过滤高倍率节点
    // --------------------------------------------------------

    if (enabled("过滤高倍率节点")) {

      if (
        /0\.5倍|0\.5x|0\.1倍|0\.1x|0\.01倍|0\.01x/i.test(name)
      ) {
        return false;
      }
    }


    // --------------------------------------------------------
    // 过滤非地区节点
    // --------------------------------------------------------

    if (enabled("过滤非地区节点")) {

      const isRegion =
        isRegionProxy(name, "HK") ||
        isRegionProxy(name, "TW") ||
        isRegionProxy(name, "JP") ||
        isRegionProxy(name, "SG") ||
        isRegionProxy(name, "US") ||
        isRegionProxy(name, "KR") ||
        isRegionProxy(name, "GB") ||
        isRegionProxy(name, "DE") ||
        isRegionProxy(name, "FR");

      if (!isRegion) {
        return false;
      }
    }


    return true;
  });
}


// ============================================================
// 创建地区策略组
// ============================================================

function createRegionGroups(config, proxies) {

  const groups = getObject(config, "proxy-groups", []);

  const regionList = [
    ["🇭🇰 香港", "HK"],
    ["🇹🇼 台湾", "TW"],
    ["🇯🇵 日本", "JP"],
    ["🇸🇬 新加坡", "SG"],
    ["🇺🇸 美国", "US"],
    ["🇰🇷 韩国", "KR"],
    ["🇬🇧 英国", "GB"],
    ["🇩🇪 德国", "DE"],
    ["🇫🇷 法国", "FR"]
  ];


  for (const [groupName, region] of regionList) {

    const nodes = getRegionNodes(proxies, region);

    if (nodes.length === 0) {
      continue;
    }


    // --------------------------------------------------------
    // 自动选择组
    // --------------------------------------------------------

    if (enabled("生成地区自动选择组")) {

      groups.push({
        name: `${groupName} 自动`,
        type: "url-test",
        proxies: nodes,
        url: "https://www.gstatic.com/generate_204",
        interval: 300,
        tolerance: 50
      });
    }


    // --------------------------------------------------------
    // 手动选择组
    // --------------------------------------------------------

    if (!enabled("隐藏地区手动选择组")) {

      groups.push({
        name: `${groupName} 手动`,
        type: "select",
        proxies: nodes
      });
    }
  }


  config["proxy-groups"] = groups;
}


// ============================================================
// 创建基础策略组
// ============================================================

function createBasicGroups(config, proxies) {

  const groups = getObject(config, "proxy-groups", []);

  const allProxyNames = proxies.map(proxy => proxy.name);


  // ----------------------------------------------------------
  // 手动选择
  // ----------------------------------------------------------

  if (enabled("手动选择")) {

    groups.push({
      name: "手动选择",
      type: "select",
      proxies: allProxyNames
    });
  }


  // ----------------------------------------------------------
  // 自动选择
  // ----------------------------------------------------------

  if (enabled("自动选择")) {

    groups.push({
      name: "自动选择",
      type: "url-test",
      proxies: allProxyNames,
      url: "https://www.gstatic.com/generate_204",
      interval: 300,
      tolerance: 50
    });
  }


  // ----------------------------------------------------------
  // 负载均衡
  // ----------------------------------------------------------

  if (enabled("负载均衡")) {

    groups.push({
      name: "负载均衡",
      type: "load-balance",
      proxies: allProxyNames,
      url: "https://www.gstatic.com/generate_204",
      interval: 300,
      strategy: "consistent-hashing"
    });
  }


  config["proxy-groups"] = groups;
}


// ============================================================
// 创建分流策略组
// ============================================================

function createRuleGroups(config, proxies) {

  const groups = getObject(config, "proxy-groups", []);

  const allProxyNames = proxies.map(proxy => proxy.name);


  const rules = [
    ["AI", "AI"],
    ["Media", "Media"],
    ["FCM", "FCM"],
    ["Google", "Google"],
    ["Microsoft", "Microsoft"],
    ["Apple", "Apple"],
    ["Telegram", "Telegram"],
    ["Steam", "Steam"],
    ["TikTok", "TikTok"],
    ["Twitter", "Twitter"],
    ["Emby", "Emby"],
    ["PikPak", "PikPak"],
    ["Spotify", "Spotify"],
    ["Crypto", "Crypto"],
    ["EHentai", "EHentai"],
    ["AdBlock", "AdBlock"]
  ];


  for (const [option, groupName] of rules) {

    if (!enabled(option)) {
      continue;
    }


    let groupProxies;


    // --------------------------------------------------------
    // 是否添加全部节点
    // --------------------------------------------------------

    if (enabled("分流组添加所有节点")) {

      groupProxies = allProxyNames;

    } else {

      groupProxies = [
        "🚀 节点选择",
        "♻️ 自动选择",
        "🇭🇰 香港 自动",
        "🇹🇼 台湾 自动",
        "🇯🇵 日本 自动",
        "🇸🇬 新加坡 自动",
        "🇺🇸 美国 自动",
        "🇰🇷 韩国 自动",
        "🇬🇧 英国 自动",
        "🇩🇪 德国 自动",
        "🇫🇷 法国 自动"
      ];
    }


    groupProxies = validProxies(
      groupProxies,
      [
        ...allProxyNames,
        ...groups.map(group => group.name)
      ]
    );


    if (groupProxies.length === 0) {
      continue;
    }


    groups.push({
      name: groupName,
      type: "select",
      proxies: groupProxies
    });
  }


  config["proxy-groups"] = groups;
}


// ============================================================
// QUIC 处理
// ============================================================

function blockQUIC(config) {

  if (!enabled("屏蔽国外QUIC")) {
    return;
  }


  const rules = getObject(config, "rules", []);


  // 避免重复添加
  const exists = rules.some(rule =>
    typeof rule === "string" &&
    rule.includes("NETWORK,UDP")
  );


  if (!exists) {

    rules.unshift(
      "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
    );
  }


  config["rules"] = rules;
}


// ============================================================
// 删除重复策略组
// ============================================================

function removeDuplicateGroups(config) {

  if (!Array.isArray(config["proxy-groups"])) {
    return;
  }


  const seen = new Set();


  config["proxy-groups"] =
    config["proxy-groups"].filter(group => {

      if (!group || !group.name) {
        return false;
      }

      if (seen.has(group.name)) {
        return false;
      }

      seen.add(group.name);

      return true;
    });
}


// ============================================================
// 主函数
// ============================================================

function main(config) {

  if (!config) {
    return config;
  }


  // ----------------------------------------------------------
  // 获取节点
  // ----------------------------------------------------------

  let proxies = Array.isArray(config.proxies)
    ? config.proxies
    : [];


  // ----------------------------------------------------------
  // 节点过滤
  // ----------------------------------------------------------

  proxies = filterProxies(proxies);


  // ----------------------------------------------------------
  // 创建基础策略组
  // ----------------------------------------------------------

  createBasicGroups(
    config,
    proxies
  );


  // ----------------------------------------------------------
  // 创建地区策略组
  // ----------------------------------------------------------

  createRegionGroups(
    config,
    proxies
  );


  // ----------------------------------------------------------
  // 创建分流策略组
  // ----------------------------------------------------------

  createRuleGroups(
    config,
    proxies
  );


  // ----------------------------------------------------------
  // 屏蔽国外 QUIC
  // ----------------------------------------------------------

  blockQUIC(config);


  // ----------------------------------------------------------
  // 删除重复策略组
  // ----------------------------------------------------------

  removeDuplicateGroups(config);


  // ----------------------------------------------------------
  // 返回修改后的配置
  // ----------------------------------------------------------

  return config;
}
```
