package org.fordes.adg.rule.enums;

import org.springframework.boot.ApplicationArguments;

import java.util.List;
import java.util.Locale;

/**
 * 对应 adblockfilters-modified 项目 adblock.py 的 --mode 参数
 */
public enum RunMode {
    /** 更新上游规则 + 生成最终规则（若已有 black.txt 会用其过滤），单趟运行时使用 */
    ALL,
    /** 仅解析规则、导出域名全量清单（build/domain.txt），供外部 SmartDNS 校验，不生成最终规则 */
    PREPARE,
    /** 读取 build/domain.txt，并发查询 SmartDNS 校验域名连通性，生成 build/black.txt */
    BLACKLIST,
    /** 更新上游规则 + 用已生成的 build/black.txt 过滤 + 生成最终规则 */
    GENERATE;

    public static RunMode from(ApplicationArguments args) {
        List<String> values = args.getOptionValues("mode");
        if (values == null || values.isEmpty()
                || values.get(0) == null || values.get(0).trim().isEmpty()) {
            return ALL;
        }
        return RunMode.valueOf(values.get(0).trim().toUpperCase(Locale.ROOT));
    }
}
