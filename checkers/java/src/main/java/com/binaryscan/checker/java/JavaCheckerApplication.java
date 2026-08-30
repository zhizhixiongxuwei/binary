package com.binaryscan.checker.java;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Java 反编译源码规则检测器的独立 Spring Boot 入口。
 *
 * <p>服务本身无数据库、无业务卷，仅接收 scanner 发送的 checker-v1 源码批次；这种边界使
 * Java 规则能够独立发布，同时避免检测器获得上传原件和其他任务数据的访问权限。</p>
 */
@SpringBootApplication
public class JavaCheckerApplication {
    public static void main(String[] args) {
        SpringApplication.run(JavaCheckerApplication.class, args);
    }
}
