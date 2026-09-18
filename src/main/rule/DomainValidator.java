package org.fordes.adg.rule;

import lombok.extern.slf4j.Slf4j;
import org.fordes.adg.rule.config.DnsValidateConfig;
import org.fordes.adg.rule.enums.RuleType;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 使用 SmartDNS 校验规则中域名的连通性，剔除无法解析（已失效）的域名规则。
 * 对应 adblockfilters-modified 项目中 blacklist.py 的能力，适配为
 * AdGuard-Rule 单趟执行流程中"聚合完成后、写文件前"的一个过滤步骤。
 */
@Slf4j
public final class DomainValidator {

    // 匹配 ||domain^、||domain^$modifiers、@@||domain^、@@||domain^| 等规范域名过滤规则
    private static final Pattern DOMAIN_FILTER_PATTERN =
            Pattern.compile("^(?:@@)?\\|\\|([^\\^\\$|]+)");

    private final DnsValidateConfig config;
    private final Resolver resolver;

    public DomainValidator(DnsValidateConfig config) {
        this.config = config;
        try {
            SimpleResolver simpleResolver = new SimpleResolver(config.getServer());
            simpleResolver.setPort(config.getPort());
            simpleResolver.setTimeout(Duration.ofMillis(config.getTimeoutMs()));
            this.resolver = simpleResolver;
        } catch (UnknownHostException e) {
            throw new IllegalStateException("无法解析 SmartDNS 地址: " + config.getServer(), e);
        }
    }

    /**
     * 对聚合结果做域名连通性校验，就地剔除失效规则
     */
    public void filter(RuleAggregator aggregator) {
        if (!config.isEnabled()) {
            log.info("域名连通性校验未启用，跳过");
            return;
        }
        if (!waitForSmartDns()) {
            log.error("SmartDNS 不可用（{}:{}），跳过本次域名连通性校验，规则将保持原样输出",
                    config.getServer(), config.getPort());
            return;
        }

        filterHosts(aggregator);
        filterDnsFilter(aggregator, RuleType.DNS_FILTER);
        filterDnsFilter(aggregator, RuleType.DNS_EXCEPTION);
    }

    private void filterHosts(RuleAggregator aggregator) {
        List<String> rules = aggregator.getRules(Collections.singletonList(RuleType.HOSTS));
        Map<String, List<String>> ruleDomains = new LinkedHashMap<>();
        Set<String> allDomains = new LinkedHashSet<>();

        for (String rule : rules) {
            String[] parts = rule.split("\\s+");
            if (parts.length < 2) {
                continue;
            }
            List<String> domains = Arrays.asList(parts).subList(1, parts.length);
            ruleDomains.put(rule, domains);
            allDomains.addAll(domains);
        }
        if (allDomains.isEmpty()) {
            return;
        }

        Set<String> deadDomains = resolveDead(allDomains);
        if (deadDomains.isEmpty()) {
            log.info("HOSTS 规则域名校验：候选 {}，全部可解析", allDomains.size());
            return;
        }

        Set<String> toRemove = new LinkedHashSet<>();
        for (Map.Entry<String, List<String>> entry : ruleDomains.entrySet()) {
            // 一行 hosts 规则里所有域名都失效才剔除该行，避免误杀共享同一 IP 的有效域名
            if (deadDomains.containsAll(entry.getValue())) {
                toRemove.add(entry.getKey());
            }
        }
        log.info("HOSTS 规则域名校验：候选 {}，失效 {}，剔除规则 {}",
                allDomains.size(), deadDomains.size(), toRemove.size());
        aggregator.removeAll(RuleType.HOSTS, toRemove);
    }

    private void filterDnsFilter(RuleAggregator aggregator, RuleType type) {
        List<String> rules = aggregator.getRules(Collections.singletonList(type));
        Map<String, String> ruleDomain = new LinkedHashMap<>();
        Set<String> allDomains = new LinkedHashSet<>();

        for (String rule : rules) {
            Matcher matcher = DOMAIN_FILTER_PATTERN.matcher(rule);
            if (!matcher.find()) {
                continue;
            }
            String domain = matcher.group(1);
            // 含通配符的域名无法直接发起 DNS 查询，跳过校验，保留规则
            if (domain.isEmpty() || domain.contains("*")) {
                continue;
            }
            ruleDomain.put(rule, domain);
            allDomains.add(domain);
        }
        if (allDomains.isEmpty()) {
            return;
        }

        Set<String> deadDomains = resolveDead(allDomains);
        if (deadDomains.isEmpty()) {
            log.info("{} 规则域名校验：候选 {}，全部可解析", type, allDomains.size());
            return;
        }

        Set<String> toRemove = new LinkedHashSet<>();
        for (Map.Entry<String, String> entry : ruleDomain.entrySet()) {
            if (deadDomains.contains(entry.getValue())) {
                toRemove.add(entry.getKey());
            }
        }
        log.info("{} 规则域名校验：候选 {}，失效 {}，剔除规则 {}",
                type, allDomains.size(), deadDomains.size(), toRemove.size());
        aggregator.removeAll(type, toRemove);
    }

    /**
     * 并发查询 SmartDNS，返回解析失败（无法拿到 A 记录）的域名集合
     */
    private Set<String> resolveDead(Set<String> domains) {
        int poolSize = Math.max(1, config.getConcurrency());
        ExecutorService executor = Executors.newFixedThreadPool(poolSize);
        Set<String> dead = ConcurrentHashMap.newKeySet();
        List<Runnable> tasks = new ArrayList<>(domains.size());

        try {
            for (String domain : domains) {
                executor.submit(() -> {
                    if (!resolves(domain)) {
                        dead.add(domain);
                    }
                });
            }
            executor.shutdown();
            // 整体等待时间随域名规模与超时/重试配置自适应放宽，避免大规模规则时提前截断
            long overallTimeoutMs = Math.max(60_000L,
                    (long) domains.size() / Math.max(1, poolSize)
                            * config.getTimeoutMs() * (config.getRetry() + 1L) + 30_000L);
            if (!executor.awaitTermination(overallTimeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                log.warn("域名校验任务未在预期时间内全部完成，已完成部分将按实际结果处理");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdownNow();
        }
        return dead;
    }

    /** 单个域名是否可解析（拿到至少一条 A 记录） */
    private boolean resolves(String domain) {
        Name name;
        try {
            name = Name.fromString(domain, Name.root);
        } catch (TextParseException e) {
            // 域名格式异常，无法校验，保留规则（不参与判定，视为"未知"而非"失效"）
            return true;
        }
        for (int attempt = 0; attempt <= config.getRetry(); attempt++) {
            Lookup lookup = new Lookup(name, Type.A);
            lookup.setResolver(resolver);
            lookup.setCache(null); // 交给 SmartDNS 自身缓存，不用 dnsjava 本地缓存
            Record[] answers = lookup.run();
            if (lookup.getResult() == Lookup.SUCCESSFUL && answers != null && answers.length > 0) {
                return true;
            }
            // 只有临时性错误（TRY_AGAIN）才重试，NXDOMAIN 等明确失败无需重试
            if (lookup.getResult() != Lookup.TRY_AGAIN) {
                break;
            }
        }
        return false;
    }

    /** 校验开始前先确认 SmartDNS 可用，避免其未就绪时把所有域名误判为失效 */
    private boolean waitForSmartDns() {
        int attempts = Math.max(1, config.getHealthCheckAttempts());
        for (int attempt = 1; attempt <= attempts; attempt++) {
            if (resolves("example.com")) {
                if (attempt > 1) {
                    log.info("SmartDNS 健康检查通过（第 {} 次尝试）", attempt);
                }
                return true;
            }
            log.warn("SmartDNS 健康检查失败，第 {}/{} 次尝试，{} ms 后重试",
                    attempt, attempts, config.getHealthCheckIntervalMs());
            try {
                Thread.sleep(config.getHealthCheckIntervalMs());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }
}
