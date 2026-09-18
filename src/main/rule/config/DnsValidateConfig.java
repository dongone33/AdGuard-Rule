package org.fordes.adg.rule.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 域名连通性校验（SmartDNS）配置
 */
@Data
@Component
@ConfigurationProperties(prefix = "application.dns-validate")
public class DnsValidateConfig {

    /** 是否启用域名连通性校验，剔除无法解析的失效域名规则 */
    private boolean enabled = false;

    /** SmartDNS 监听地址 */
    private String server = "127.0.0.1";

    /** SmartDNS 监听端口 */
    private int port = 5053;

    /** 单次查询超时时间（毫秒） */
    private long timeoutMs = 3000;

    /** 查询失败重试次数 */
    private int retry = 2;

    /** 并发查询线程数 */
    private int concurrency = 200;

    /** 校验开始前的健康检查最大尝试次数 */
    private int healthCheckAttempts = 10;

    /** 健康检查失败后的重试等待间隔（毫秒） */
    private long healthCheckIntervalMs = 3000;
}
