package com.binaryscan.checker.c;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * C/C++ 伪源码检测器的独立进程入口。
 *
 * <p>该服务不直接访问 BinaryScan 的数据库和业务文件卷，只暴露内部 HTTP 健康检查与
 * {@code checker-v1} 检测接口。scanner 负责读取反编译产物、组装请求并持久化 Finding，
 * 因而检测器可以保持无状态，也可以在不迁移业务数据的情况下单独升级或回滚。</p>
 */
@SpringBootApplication
public class CCheckerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CCheckerApplication.class, args);
    }
}
