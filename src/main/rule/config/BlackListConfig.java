package org.fordes.adg.rule.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "application.blacklist")
public class BlackListConfig {

    private String buildDir = "build";
    private String domainFile = "domain.txt";
    private String blackFile = "black.txt";

    private String server = "127.0.0.1";
    private int port = 5053;

    /** 单次查询超时（毫秒），对应 python __dns_timeout */
    private long timeoutMs = 5000;
    /** 单域名总耗时上限（毫秒），对应 python __dns_lifetime */
    private long lifetimeMs = 8000;
    /** 并发查询数，对应 python __maxTask */
    private int maxConcurrency = 500;
    /** 每批域名数，0 表示不分批，对应 python __health_check_interval */
    private int batchSize = 30000;

    private long healthCheckTimeoutMs = 5000;
    /** 健康检查失败后的初始等待（秒），指数退避，上限 60s，对应 python __health_check_sleep */
    private long healthCheckSleepSeconds = 5;
    /** 健康检查最长等待（秒），超过判定 SmartDNS 不可用，对应 python __health_check_max_wait */
    private long healthCheckMaxWaitSeconds = 600;

    /** SmartDNS 可执行文件+配置所在目录，用于批次间重启；留空则跳过重启，只等待其自愈 */
    private String smartDnsPath = "";
}
