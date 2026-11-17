package com.binaryscan.checker.java;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/** Version-bound normal-return contracts. A framework label is never evidence. */
final class FrameworkContracts {
    static final String VERSION = "framework-contracts-v1";
    enum PredicateKind { NONE, NULL, NOT_NULL, EMPTY, NOT_EMPTY }
    enum ReturnKind { UNKNOWN, NORMAL_NON_NULL, NULLABLE, PASSTHROUGH, NULLNESS_OF_ARGUMENT }
    record ReturnContract(ReturnKind kind, int argumentIndex, String modelId) {}
    private static final ReturnContract UNKNOWN = new ReturnContract(ReturnKind.UNKNOWN, -1, "");
    private final Map<String,String> frameworks;
    private final String frameworksDigest;

    FrameworkContracts(Map<String,String> frameworks) {
        var sorted = new TreeMap<String,String>();
        if (frameworks != null) {
            if (frameworks.size() > 512) throw new IllegalArgumentException("framework metadata exceeds the entry limit");
            for (var entry : frameworks.entrySet()) {
                String coordinate = entry.getKey(), version = entry.getValue();
                if (coordinate == null || coordinate.length() > 256 || !coordinate.matches("[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+")
                    || version == null || version.length() > 128 || !version.matches("[A-Za-z0-9_.+!\\-]+"))
                    throw new IllegalArgumentException("invalid framework coordinate or version");
                sorted.put(coordinate, version);
            }
        }
        this.frameworks = Collections.unmodifiableMap(sorted);
        this.frameworksDigest = digestJson(sorted);
    }

    String version() { return VERSION; }
    String frameworksSha256() { return frameworksDigest; }
    String modelDigest() { return sha256((VERSION + "\n" + frameworksDigest).getBytes(StandardCharsets.UTF_8)); }
    Map<String,String> frameworks() { return frameworks; }
    String dependencyVersion(String modelOrOwner) {
        if (modelOrOwner.startsWith("jdk21-") || modelOrOwner.startsWith("java.")) return "21";
        if (modelOrOwner.startsWith("hutool-") || modelOrOwner.startsWith("cn.hutool.")) return supports("cn.hutool:hutool-core") ? frameworks.getOrDefault("cn.hutool:hutool-core", frameworks.getOrDefault("cn.hutool:hutool-all", "")) : "";
        if (modelOrOwner.startsWith("mybatis-plus-") || modelOrOwner.startsWith("com.baomidou.")) return supports("com.baomidou:mybatis-plus-core") ? frameworks.get("com.baomidou:mybatis-plus-core") : "";
        if (modelOrOwner.startsWith("mybatis-") || modelOrOwner.startsWith("org.apache.ibatis.")) return supports("org.mybatis:mybatis") ? frameworks.get("org.mybatis:mybatis") : "";
        if (modelOrOwner.startsWith("mapstruct-plus-") || modelOrOwner.startsWith("io.github.linpeilie.")) return supports("io.github.linpeilie:mapstruct-plus") ? frameworks.get("io.github.linpeilie:mapstruct-plus") : "";
        if (modelOrOwner.startsWith("spring-") || modelOrOwner.startsWith("org.springframework.")) return frameworks.entrySet().stream().filter(e -> e.getKey().startsWith("org.springframework:") && supports(e.getKey())).map(Map.Entry::getValue).findFirst().orElse("");
        return modelOrOwner.startsWith("java-nullness-") ? NullDereferenceAnalyzer.MODEL_VERSION : "";
    }

    // Only call after proving a MyBatis mapper/proxy receiver. A Map return is
    // not a collection query without @MapKey; it may be a nullable single row.
    ReturnContract mapperReturn(String returnType, List<String> argumentTypes) {
        if (!supports("org.mybatis:mybatis")) return UNKNOWN;
        String returned = base(returnType);
        if (Set.of("java.util.List", "java.util.Collection", "java.util.Set", "java.util.ArrayList", "java.util.LinkedList", "java.util.HashSet").contains(returned) || returned.endsWith("[]")) return normal("mybatis-3.5.16-proxy-container");
        if (returned.equals("java.util.Optional")) return normal("mybatis-3.5.16-proxy-optional");
        if (supports("com.baomidou:mybatis-plus-core") && Set.of("com.baomidou.mybatisplus.core.metadata.IPage", "com.baomidou.mybatisplus.extension.plugins.pagination.Page").contains(returned)
            && argumentTypes.stream().map(FrameworkContracts::base).anyMatch(t -> Set.of("com.baomidou.mybatisplus.core.metadata.IPage", "com.baomidou.mybatisplus.extension.plugins.pagination.Page").contains(t))) return normal("mybatis-plus-3.5.6-proxy-page");
        if (Set.of("void", "boolean", "byte", "short", "int", "long", "float", "double", "char").contains(returned)) return UNKNOWN;
        return nullable("mybatis-3.5.16-single-result");
    }
    boolean exact(String coordinate, String version) { return version.equals(frameworks.get(coordinate)); }
    boolean supports(String coordinate) {
        return switch (coordinate) {
            case "org.springframework:spring-core", "org.springframework:spring-beans", "org.springframework:spring-context", "org.springframework:spring-web", "org.springframework:spring-webmvc" -> exact(coordinate, "6.1.8");
            case "org.mybatis:mybatis" -> exact(coordinate, "3.5.16");
            case "com.baomidou:mybatis-plus-core", "com.baomidou:mybatis-plus-extension" -> exact(coordinate, "3.5.6");
            case "cn.hutool:hutool-core", "cn.hutool:hutool-all" ->
                (exact("cn.hutool:hutool-core", "5.8.27") || exact("cn.hutool:hutool-all", "5.8.27"))
                    && (!frameworks.containsKey("cn.hutool:hutool-core") || exact("cn.hutool:hutool-core", "5.8.27"))
                    && (!frameworks.containsKey("cn.hutool:hutool-all") || exact("cn.hutool:hutool-all", "5.8.27"));
            case "io.github.linpeilie:mapstruct-plus", "io.github.linpeilie:mapstruct-plus-spring-boot-starter" -> exact(coordinate, "1.3.6");
            default -> false;
        };
    }

    PredicateKind predicate(String owner, String name, int arity) {
        if (arity != 1) return PredicateKind.NONE;
        if (owner.equals("java.util.Objects")) return switch (name) {
            case "isNull" -> PredicateKind.NULL; case "nonNull" -> PredicateKind.NOT_NULL; default -> PredicateKind.NONE;
        };
        if (supports("cn.hutool:hutool-core")) {
            if (Set.of("cn.hutool.core.util.ObjectUtil", "cn.hutool.core.util.ObjUtil").contains(owner)) return switch (name) {
                // Hutool also invokes equals(null). Only one direction proves
                // non-null; the opposite branch need not contain a null value.
                case "isNull" -> PredicateKind.EMPTY; case "isNotNull" -> PredicateKind.NOT_EMPTY;
                case "isEmpty" -> PredicateKind.EMPTY; case "isNotEmpty" -> PredicateKind.NOT_EMPTY; default -> PredicateKind.NONE;
            };
            if (Set.of("cn.hutool.core.collection.CollUtil", "cn.hutool.core.collection.CollectionUtil", "cn.hutool.core.map.MapUtil", "cn.hutool.core.util.StrUtil", "cn.hutool.core.text.CharSequenceUtil").contains(owner)) return switch (name) {
                case "isEmpty", "isBlank" -> PredicateKind.EMPTY; case "isNotEmpty", "isNotBlank" -> PredicateKind.NOT_EMPTY; default -> PredicateKind.NONE;
            };
        }
        if (supports("org.springframework:spring-core")) {
            if (owner.equals("org.springframework.util.CollectionUtils") && name.equals("isEmpty")) return PredicateKind.EMPTY;
            if (owner.equals("org.springframework.util.StringUtils") && Set.of("hasLength", "hasText").contains(name)) return PredicateKind.NOT_EMPTY;
        }
        return PredicateKind.NONE;
    }

    ReturnContract method(String owner, String name, List<String> argumentTypes, String returnType) {
        int arity = argumentTypes.size();
        String returned = base(returnType);
        if (Set.of("java.util.List", "java.util.Set", "java.util.Map").contains(owner)
            && (name.equals("of") || name.equals("copyOf") && arity == 1)) return normal("jdk21-immutable-container");
        if (owner.equals("java.util.Collections") && (Set.of("emptyList", "emptySet", "emptyMap", "emptyIterator", "emptyEnumeration").contains(name) && arity == 0
            || Set.of("singletonList", "singleton", "unmodifiableList", "unmodifiableSet", "unmodifiableMap", "synchronizedList", "synchronizedSet", "synchronizedMap").contains(name) && arity == 1
            || name.equals("singletonMap") && arity == 2)) return normal("jdk21-collection-container");
        if (Set.of("java.util.Map", "java.util.HashMap", "java.util.LinkedHashMap", "java.util.TreeMap", "java.util.concurrent.ConcurrentMap", "java.util.concurrent.ConcurrentHashMap").contains(owner)
            && (name.equals("get") && arity == 1 || name.equals("getOrDefault") && arity == 2)) return nullable("jdk21-map-value");
        if (Set.of("java.util.Collection", "java.util.List", "java.util.Set", "java.util.ArrayList", "java.util.LinkedList").contains(owner)
            && Set.of("iterator", "stream", "parallelStream", "toArray", "listIterator", "subList").contains(name)) return normal("jdk21-collection-container");

        if (supports("cn.hutool:hutool-core")) {
            if (Set.of("cn.hutool.core.collection.CollUtil", "cn.hutool.core.collection.CollectionUtil", "cn.hutool.core.collection.ListUtil").contains(owner)
                && Set.of("newArrayList", "newLinkedList", "newHashSet", "newLinkedHashSet", "empty", "emptyIfNull", "toList", "toLinkedList").contains(name)) return normal("hutool-5.8.27-container");
            if (owner.equals("cn.hutool.core.map.MapUtil") && Set.of("newHashMap", "newTreeMap", "empty", "emptyIfNull").contains(name)) return normal("hutool-5.8.27-map-container");
            // defaultIfNull/defaultIfBlank depend on *both* arguments. Leave them
            // to conditional flow, never claim an unconditional non-null value.
        }
        if (supports("org.springframework:spring-beans") && Set.of("org.springframework.beans.factory.BeanFactory", "org.springframework.beans.factory.ListableBeanFactory", "org.springframework.beans.factory.support.DefaultListableBeanFactory").contains(owner)
            && name.equals("getBean") && arity >= 1) return normal("spring-6.1.8-bean-lookup");
        if (supports("org.springframework:spring-context")) {
            if (Set.of("org.springframework.context.ApplicationContext", "org.springframework.context.ConfigurableApplicationContext").contains(owner) && name.equals("getBean") && arity >= 1) return normal("spring-6.1.8-bean-lookup");
            if (owner.equals("org.springframework.cache.CacheManager") && name.equals("getCache") && arity == 1) return nullable("spring-6.1.8-cache-region");
            if (owner.equals("org.springframework.cache.Cache") && name.equals("get") && arity >= 1) return nullable("spring-6.1.8-cache-value");
            if (Set.of("org.springframework.validation.Errors", "org.springframework.validation.BindingResult", "org.springframework.validation.BindException").contains(owner)
                && Set.of("getFieldError", "getGlobalError").contains(name)) return nullable("spring-6.1.8-validation-error");
        }
        if (supports("org.springframework:spring-beans") && owner.equals("org.springframework.beans.TypeMismatchException") && name.equals("getRequiredType") && arity == 0) return nullable("spring-6.1.8-required-type");
        if (supports("org.springframework:spring-web") && owner.equals("org.springframework.web.multipart.MultipartFile") && name.equals("getOriginalFilename") && arity == 0) return nullable("spring-6.1.8-multipart-filename");
        if (supports("org.springframework:spring-webmvc") && owner.equals("org.springframework.web.servlet.HandlerMapping") && name.equals("getHandler") && arity == 1) return nullable("spring-6.1.8-handler-mapping");

        if (supports("org.mybatis:mybatis") && Set.of("org.apache.ibatis.session.SqlSession", "org.apache.ibatis.session.defaults.DefaultSqlSession").contains(owner)) {
            if (Set.of("selectList", "selectMap").contains(name) && arity >= 1 && arity <= 3) return normal("mybatis-3.5.16-query-container");
            if (name.equals("selectOne") && arity >= 1 && arity <= 2) return nullable("mybatis-3.5.16-single-result");
        }
        if (supports("com.baomidou:mybatis-plus-core") && owner.equals("com.baomidou.mybatisplus.core.mapper.BaseMapper")) {
            if (Set.of("selectList", "selectMaps", "selectObjs", "selectBatchIds", "selectByMap").contains(name) && Set.of("java.util.List", "List").contains(returned)) return normal("mybatis-plus-3.5.6-query-container");
            if (name.equals("selectPage") && arity == 2) return normal("mybatis-plus-3.5.6-page-container");
            if (Set.of("selectById", "selectOne").contains(name)) return nullable("mybatis-plus-3.5.6-single-result");
        }
        if (supports("io.github.linpeilie:mapstruct-plus") && owner.equals("io.github.linpeilie.Converter") && name.equals("convert") && arity == 2) {
            if (Set.of("java.util.List", "List").contains(base(argumentTypes.getFirst())) && Set.of("java.lang.Class", "Class").contains(base(argumentTypes.get(1)))) return normal("mapstruct-plus-1.3.6-list-container");
            // Scalar conversion delegates to a user-extensible BaseMapper. Map
            // conversion also returns null for empty/all-null input. The version
            // alone cannot prove either result non-null.
            if (Set.of("java.util.Map", "Map").contains(base(argumentTypes.getFirst()))) return nullable("mapstruct-plus-1.3.6-map-result");
        }
        return UNKNOWN;
    }

    private static ReturnContract normal(String id) { return new ReturnContract(ReturnKind.NORMAL_NON_NULL, -1, id); }
    private static ReturnContract nullable(String id) { return new ReturnContract(ReturnKind.NULLABLE, -1, id); }
    private static String base(String type) { return type == null ? "" : type.replaceAll("<.*>", "").strip(); }
    static String digestJson(Map<String,String> values) {
        try { return sha256(new ObjectMapper().writeValueAsBytes(new TreeMap<>(values))); }
        catch (Exception failure) { throw new IllegalArgumentException("could not canonicalize framework metadata", failure); }
    }
    static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
