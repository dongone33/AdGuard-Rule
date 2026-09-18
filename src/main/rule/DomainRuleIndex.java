package org.fordes.adg.rule;

import org.fordes.adg.rule.enums.RuleType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 从聚合结果中抽取"规则 -> 候选域名"的映射。
 * HOSTS: "ip domain1 [domain2 ...]"
 * DNS_FILTER / DNS_EXCEPTION: "||domain^..." / "@@||domain^..."
 * REGEX、MODIFY 无法可靠抽取单一目标域名，不参与校验。
 */
public final class DomainRuleIndex {

    private static final Pattern DOMAIN_FILTER_PATTERN =
            Pattern.compile("^(?:@@)?\\|\\|([^\\^\\$|]+)");

    private static final List<RuleType> DOMAIN_RULE_TYPES =
            Arrays.asList(RuleType.HOSTS, RuleType.DNS_FILTER, RuleType.DNS_EXCEPTION);

    private final Map<RuleType, Map<String, List<String>>> index = new LinkedHashMap<>();

    private DomainRuleIndex() {
    }

    public static DomainRuleIndex build(RuleAggregator aggregator) {
        DomainRuleIndex result = new DomainRuleIndex();
        for (RuleType type : DOMAIN_RULE_TYPES) {
            Map<String, List<String>> ruleDomains = new LinkedHashMap<>();
            for (String rule : aggregator.getRules(Collections.singletonList(type))) {
                List<String> domains = type == RuleType.HOSTS
                        ? extractHostsDomains(rule)
                        : extractFilterDomain(rule);
                if (!domains.isEmpty()) {
                    ruleDomains.put(rule, domains);
                }
            }
            result.index.put(type, ruleDomains);
        }
        return result;
    }

    private static List<String> extractHostsDomains(String rule) {
        String[] parts = rule.split("\\s+");
        if (parts.length < 2) {
            return Collections.emptyList();
        }
        return Arrays.asList(parts).subList(1, parts.length);
    }

    private static List<String> extractFilterDomain(String rule) {
        Matcher matcher = DOMAIN_FILTER_PATTERN.matcher(rule);
        if (!matcher.find()) {
            return Collections.emptyList();
        }
        String domain = matcher.group(1);
        if (domain.isEmpty() || domain.contains("*")) {
            return Collections.emptyList(); // 通配符域名无法直接查询，跳过
        }
        return Collections.singletonList(domain);
    }

    /** 全量候选域名，对应 python 的 domain.txt 内容 */
    public Set<String> allDomains() {
        Set<String> all = new LinkedHashSet<>();
        for (Map<String, List<String>> ruleDomains : index.values()) {
            for (List<String> domains : ruleDomains.values()) {
                all.addAll(domains);
            }
        }
        return all;
    }

    /**
     * 按黑名单集合找出应剔除的规则键，按类型分组。
     * 一条规则涉及多个域名时，只有全部域名都在黑名单中才剔除，
     * 对应 python filter.py 中 all(domain in blackSet ...) 的保守策略。
     */
    public Map<RuleType, Set<String>> rulesToRemove(Set<String> blackSet) {
        Map<RuleType, Set<String>> result = new LinkedHashMap<>();
        for (Map.Entry<RuleType, Map<String, List<String>>> entry : index.entrySet()) {
            Set<String> toRemove = new LinkedHashSet<>();
            for (Map.Entry<String, List<String>> ruleEntry : entry.getValue().entrySet()) {
                if (blackSet.containsAll(ruleEntry.getValue())) {
                    toRemove.add(ruleEntry.getKey());
                }
            }
            if (!toRemove.isEmpty()) {
                result.put(entry.getKey(), toRemove);
            }
        }
        return result;
    }
}
