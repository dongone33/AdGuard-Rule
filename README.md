<div align="center">
<h1>AdGuard Rule-modified </h1>
  <p>
    一个简易的Java程序，用于合并与更新 AdGuard 过滤规则
</p>
</div>


<h2 id="a">📔 说明</h2>

本项目旨在按需求整合 `AdGuard` 规则。定时从上游订阅获取规则，去除`重复`和`不受支持`的规则并进行分类。如果存在误杀请手动放行。  
支持`AdGuard`、`AdGuard Home`,每`12小时`自动更新一次

#### 改进说明

使用 Smartdns 构建国内、国外各 3 组 DNS 服务，分别对上游各规则源拦截的域名进行解析，去除已无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）

#### 上游规则

<details>
<summary>点击查看</summary>
<ul>
<!-- Adguard基础规则 -->
<li><a href="https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt">AdGuard Base filter</a></li>
<li><a href="https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt">AdGuard Chinese filter</a></li>
<li><a href="https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt">AdGuard Mobile Ads filter</a></li>
<li><a href="https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt">AdGuard DNS filter</a></li>
<li><a href="https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/refs/heads/main/filters/other/filter_7_SmartTVBlocklist/filter.txt">SmartTV</a></li>

<!-- 自用添加 -->
<li><a href="https://anti-ad.net/easylist.txt">anti-AD</a></li>
<li><a href="https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt">AWAvenue Ads Rule</a></li>
<li><a href="https://cdn.jsdelivr.net/gh/sbwml/halflife-list@master/ad.txt">HalfLife</a></li>
<li><a href="https://raw.githubusercontent.com/afwfv/DD-AD/refs/heads/release/easylist.txt">DD-AD</a></li>
<li><a href="https://raw.githubusercontent.com/rssvcn/qy-Ads-Rule/main/black.txt">晴雅广告拦截规则</a></li>
<li><a href="https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt">jiekouAD</a></li>
<li><a href="https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts">SMAdHosts</a></li>
<li><a href="https://raw.githubusercontent.com/qq5460168/666/refs/heads/master/rules.txt">那个谁520规则</a></li>
<li><a href="https://raw.githubusercontent.com/TTDNS/Cat/refs/heads/main/DNS.TXT">TTDNS</a></li>
<li><a href="https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/FuLingRules/FuLingBlockList.txt">茯苓广告规则</a></li>
<li><a href="https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt">HG</a></li>
<li><a href="https://raw.githubusercontent.com/Kuner-mw/DNS-Kuner/main/FilterRules/blacklist.txt">DNS-Kuner拦截列表</a></li>
<li><a href="https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt">Cats-Team/AdRules规则</a></li>

<!-- 隐私保护 -->
<li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt">HaGeZi's Apple Tracker Blocklist</a></li>
<li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt">HaGeZi's Xiaomi Tracker Blocklist</a></li>
<li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt">HaGeZi's Vivo Tracker Blocklist</a></li>
<li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt">HaGeZi's Samsung Tracker Blocklist</a></li>
<li><a href="https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/refs/heads/main/filters/other/filter_66_HageziOppoRealmeTrackerBlocklist/filter.txt">HaGeZi's OPPO & Realme Tracker Blocklist</a></li>

<!-- 白名单规则 -->
<li><a href="https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/FuLingRules/FuLingAllowList.txt">茯苓允许列表</a></li>
<li><a href="https://raw.githubusercontent.com/afwfv/DD-AD/refs/heads/release/DD-AD.txt">DD-AD允许列表</a></li>
<li><a href="https://raw.githubusercontent.com/qq5460168/666/master/allow.txt">那个谁520广告白名单</a></li>
<li><a href="https://raw.githubusercontent.com/Kuner-mw/DNS-Kuner/main/FilterRules/allowlist.txt">DNS-Kuner放行列表</a></li>
</ul>
</details>

#### 本地规则

- [mylist](#)
> 主要是对上游规则的修正补充，根据日常使用体验，解除一些失误拦截

<h2 id="b">🎯 订阅</h2>

| 名称           | 说明                                                | Github Raw                                                                              | jsDelivr CDN                                                                        |
|---------------|-----------------------------------------------------|-----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `all.txt`    | 去重的规则合集，包含以下所有规则，适用于 `AdGuard` 客户端                | [✈️点击查看](https://raw.githubusercontent.com/dongone33/AdGuard-Rule/main/rule/all.txt)      | [🚀点击查看](https://cdn.jsdelivr.net/gh/dongone33/AdGuard-Rule@main/rule/all.txt)    |
| `adgh.txt`   | 针对 `AdGuardHome` 的规则，包含 `domain.txt`、`regex.txt` 和 `mylist.txt`，可与 `hosts.txt` 配合使用 | [✈️点击查看](https://raw.githubusercontent.com/dongone33/AdGuard-Rule/main/rule/adgh.txt)   | [🚀点击查看](https://cdn.jsdelivr.net/gh/dongone33/AdGuard-Rule/main/rule/adgh.txt)   |
| `domain.txt` | 域名规则，`AdGuard`和`AdGuardHome`都支持                                       | [✈️点击查看](https://raw.githubusercontent.com/dongone33/AdGuard-Rule/main/rule/domain.txt) | [🚀点击查看](https://cdn.jsdelivr.net/gh/dongone33/AdGuard-Rule@main/rule/domain.txt) |
| `hosts.txt`  | `hosts` 规则，~~包含一些访问加速~~                           | [✈️点击查看](https://raw.githubusercontent.com/dongone33/AdGuard-Rule/main/rule/hosts.txt)  | [🚀点击查看](https://cdn.jsdelivr.net/gh/dongone33/AdGuard-Rule@main/rule/hosts.txt)  |
| `modify.txt` | 修饰规则，`AdGuard`支持                                      | [✈️点击查看](https://raw.githubusercontent.com/dongone33/AdGuard-Rule/main/rule/modify.txt) | [🚀点击查看](https://cdn.jsdelivr.net/gh/dongone33/AdGuard-Rule@main/rule/modify.txt) |
| `regex.txt` | 正则规则，`AdGuard`和`AdGuardHome`都支持                                       | [✈️点击查看](https://raw.githubusercontent.com/dongone33/AdGuard-Rule/main/rule/regex.txt) | [🚀点击查看](https://cdn.jsdelivr.net/gh/dongone33/AdGuard-Rule@main/rule/regex.txt) |
| `mylist.txt` | 对上游规则的修正补充，根据日常使用体验，解除一些误拦截(手动更新)                                       | [✈️点击查看](https://raw.githubusercontent.com/dongone33/AdGuard-Rule/main/rule/mylist.txt) | [🚀点击查看](https://cdn.jsdelivr.net/gh/dongone33/AdGuard-Rule@main/rule/mylist.txt) |

<br/>
<h2 id="c">🛠️ 配置</h2>

#### 示例配置

```yaml
application:
  rule:       
    #远程规则订阅，仅支持http、https
    remote:
      - 'https://example.com/list.txt'
    #本地规则，请将文件移动到项目路径rule目录中
    local: 
      - 'mylist.txt'
  output:
    path: rule   #规则文件输出路径，相对路径默认从 项目目录开始
    files:
      all.txt:    #输出文件名
        - DOMAIN  #域名规则，仅完整域名
        - REGEX   #正则规则，包含正则的域名规则，AdGH支持
        - MODIFY  #修饰规则，添加了一些修饰符号的规则，AdG支持
        - HOSTS   #Hosts规则
```

#### 使用 Github Action

- fork本项目
- 参照示例配置，修改配置文件: `src/main/resources/application.yml`，注意本地规则文件应放入项目根目录 `rule` 文件夹
- 编辑 `.github/workflows/auto-update.yml` 文件，将 `Commit Changes` 区块下邮箱与用户名修改为自己的（Github邮箱与用户名）
- 提交所有修改并等待 `Github Action` 执行，执行完成后相应规则生成在配置中指定的目录下

<br/>
<h2 id="c">🧭 支持</h2>

<table>
  <tr>
    <td><a href="https://dartnode.com?aff=GrumpySalamander981"><img src="./src/img/DartNode.png" width="350" height="150" border="0" alt="Stop Overpaying Start Sharing Save More with DolOffer"></a></td>
    <td><a href="https://doloffer.com/friend/0ApoCZTz"><img src="./src/img/DolOffer.png" width="350" height="150" border="0" alt="Stop Overpaying Start Sharing Save More with DolOffer"></a></td>
  </tr>
</table>
