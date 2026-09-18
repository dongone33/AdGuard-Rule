package org.fordes.adg.rule;

import lombok.extern.slf4j.Slf4j;
import org.fordes.adg.rule.config.BlackListConfig;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * 读取全量域名清单，通过本地 SmartDNS 并发解析域名连通性，
 * 把无法解析的域名写入黑名单文件，供 generate 阶段剔除对应规则。
 * 完全独立于规则拉取/聚合逻辑，对应 python scripts/blacklist.py。
 */
@Slf4j
public final class BlackListGenerator {

    private final BlackListConfig config;
    private final Path domainFile;
    private final Path blackFile;

    public BlackListGenerator(BlackListConfig config) {
        this.config = config;
        Path buildDir = Util.resolvePath(config.getBuildDir());
        this.domainFile = buildDir.resolve(config.getDomainFile());
        this.blackFile = buildDir.resolve(config.getBlackFile());
    }

    public void generate() throws IOException {
        List<String> domainList = readDomainList();
        if (domainList.isEmpty()) {
            log.info("域名清单为空，跳过黑名单生成: {}", domainFile);
            return;
        }
        log.info("待校验域名: {}", domainList.size());

        Set<String> deadDomains = testDomainBatches(domainList);
        writeBlackList(deadDomains);
        log.info("黑名单生成完成，失效域名: {} 个", deadDomains.size());
    }

    private List<String> readDomainList() throws IOException {
        if (!Files.exists(domainFile)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (String line : Files.readAllLines(domainFile, StandardCharsets.UTF_8)) {
            String domain = line.trim();
            if (!domain.isEmpty()) {
                result.add(domain);
            }
        }
        return result;
    }

    private void writeBlackList(Set<String> deadDomains) throws IOException {
        Files.createDirectories(blackFile.getParent());
        List<String> sorted = new ArrayList<>(deadDomains);
        sorted.sort(String::compareTo);
        Files.write(blackFile, sorted, StandardCharsets.UTF_8);
    }

    /** 分批解析：批前健康检查，批间视配置重启 SmartDNS，对应 python __testDomainBatches */
    private Set<String> testDomainBatches(List<String> domainList) {
        int batchSize = config.getBatchSize() > 0 ? config.getBatchSize() : domainList.size();
        waitForSmartDns();

        Set<String> dead = new LinkedHashSet<>();
        int total = domainList.size();
        for (int start = 0; start < total; start += batchSize) {
            int end = Math.min(start + batchSize, total);
            log.info("解析域名批次: {}-{}/{}", start + 1, end, total);
            dead.addAll(testDomain(domainList.subList(start, end)));
            if (end < total) {
                if (restartSmartDns()) {
                    waitForSmartDns();
                }
            }
        }
        return dead;
    }

    /** 并发解析一批域名，返回解析失败的域名集合，对应 python __testDomain */
    private Set<String> testDomain(List<String> domainList) {
        Resolver resolver;
        try {
            resolver = buildResolver(config.getTimeoutMs());
        } catch (UnknownHostException e) {
            log.error("无法连接 SmartDNS: {}", e.getMessage());
            return new LinkedHashSet<>(domainList);
        }

        int poolSize = Math.max(1, Math.min(config.getMaxConcurrency(), domainList.size()));
        ExecutorService executor = Executors.newFixedThreadPool(poolSize);
        List<Future<String>> futures = new ArrayList<>(domainList.size());
        Set<String> dead = new LinkedHashSet<>();

        try {
            for (String domain : domainList) {
                Callable<String> task = () -> resolves(domain, resolver) ? null : domain;
                futures.add(executor.submit(task));
            }
            long perTaskTimeout = config.getLifetimeMs() + 2000;
            for (Future<String> future : futures) {
                try {
                    String failedDomain = future.get(perTaskTimeout, TimeUnit.MILLISECONDS);
                    if (failedDomain != null) {
                        dead.add(failedDomain);
                    }
                } catch (Exception e) {
                    // 单个任务超时/异常不计入失效，保守处理，避免误杀
                }
            }
        } finally {
            executor.shutdownNow();
        }

        int resolved = domainList.size() - dead.size();
        log.info("批次解析结果: 总数={}, 成功={}, 失败={}", domainList.size(), resolved, dead.size());
        return dead;
    }

    private boolean resolves(String domain, Resolver resolver) {
        Name name;
        try {
            name = Name.fromString(domain, Name.root);
        } catch (TextParseException e) {
            return true; // 域名格式异常，不参与判定
        }
        Lookup lookup = new Lookup(name, Type.A);
        lookup.setResolver(resolver);
        lookup.setCache(null);
        Record[] answers = lookup.run();
        return lookup.getResult() == Lookup.SUCCESSFUL && answers != null && answers.length > 0;
    }

    private Resolver buildResolver(long timeoutMs) throws UnknownHostException {
        SimpleResolver resolver = new SimpleResolver(config.getServer());
        resolver.setPort(config.getPort());
        resolver.setTimeout(Duration.ofMillis(timeoutMs));
        return resolver;
    }

    /** 单次健康检查，对应 python __check_smartdns */
    private boolean checkSmartDns() {
        try {
            Resolver resolver = buildResolver(config.getHealthCheckTimeoutMs());
            return resolves("example.com", resolver);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /** 等待 SmartDNS 恢复健康，指数退避，超时抛异常，对应 python __wait_for_smartdns */
    private void waitForSmartDns() {
        long start = System.currentTimeMillis();
        long delaySeconds = config.getHealthCheckSleepSeconds();
        int attempt = 0;
        while (true) {
            if (checkSmartDns()) {
                if (attempt > 0) {
                    log.info("SmartDNS 恢复健康（第 {} 次尝试）", attempt);
                }
                return;
            }
            attempt++;
            log.warn("SmartDNS 不健康（第 {} 次尝试），{} 秒后重试", attempt, delaySeconds);
            sleep(delaySeconds);
            if ((System.currentTimeMillis() - start) / 1000 >= config.getHealthCheckMaxWaitSeconds()) {
                throw new IllegalStateException(
                        "SmartDNS 在 " + config.getHealthCheckMaxWaitSeconds() + " 秒内未恢复健康");
            }
            delaySeconds = Math.min(delaySeconds * 2, 60);
        }
    }

    /** 停止 SmartDNS 进程，对应 python __stop_smartdns */
    private void stopSmartDns() {
        try {
            boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
            ProcessBuilder pb = windows
                    ? new ProcessBuilder("taskkill", "/f", "/im", "smartdns.exe")
                    : new ProcessBuilder("pkill", "-f", "smartdns");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            process.waitFor(10, TimeUnit.SECONDS);
            Thread.sleep(1000);
        } catch (Exception e) {
            log.warn("停止 SmartDNS 失败: {}", e.getMessage());
        }
    }

    /** 重启 SmartDNS 进程，对应 python __restart_smartdns */
    private boolean restartSmartDns() {
        String smartDnsPath = config.getSmartDnsPath();
        if (smartDnsPath == null || smartDnsPath.trim().isEmpty()) {
            return false; // 未配置管理路径，不具备重启能力
        }
        Path binPath = Paths.get(smartDnsPath, "smartdns");
        Path confPath = Paths.get(smartDnsPath, "smartdns.conf");
        if (!Files.exists(binPath) || !Files.exists(confPath)) {
            log.warn("SmartDNS 可执行文件或配置文件不存在: {} / {}", binPath, confPath);
            return false;
        }
        stopSmartDns();
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    binPath.toString(), "-f", "-x", "-c", confPath.toString());
            pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            pb.start();
            Thread.sleep(2000);
            log.info("SmartDNS 已重启");
            return true;
        } catch (Exception e) {
            log.warn("SmartDNS 重启失败: {}", e.getMessage());
            return false;
        }
    }

    private void sleep(long seconds) {
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
