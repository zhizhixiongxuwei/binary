package frameworks

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Dependencies are recognized by precise metadata coordinates, never a JAR's
// basename. Manifest fallback is additionally bound to an exact module name and
// a real class header; it covers official Gradle artifacts without Maven props.
var supported = func() map[string]bool {
	result := map[string]bool{}
	groups := map[string][]string{
		"org.springframework.boot": {"spring-boot", "spring-boot-autoconfigure", "spring-boot-actuator", "spring-boot-actuator-autoconfigure", "spring-boot-starter", "spring-boot-starter-web", "spring-boot-starter-webflux", "spring-boot-starter-jdbc", "spring-boot-starter-validation", "spring-boot-starter-aop", "spring-boot-starter-json", "spring-boot-starter-tomcat"},
		"org.springframework":      {"spring-core", "spring-beans", "spring-context", "spring-aop", "spring-expression", "spring-web", "spring-webmvc", "spring-webflux", "spring-tx", "spring-jdbc", "spring-orm", "spring-context-support", "spring-messaging", "spring-oxm", "spring-jcl", "spring-test"},
		"org.mybatis":              {"mybatis", "mybatis-spring"},
		"org.mybatis.spring.boot":  {"mybatis-spring-boot-starter", "mybatis-spring-boot-autoconfigure"},
		"com.baomidou":             {"mybatis-plus", "mybatis-plus-core", "mybatis-plus-extension", "mybatis-plus-annotation", "mybatis-plus-spring", "mybatis-plus-spring-boot-autoconfigure", "mybatis-plus-boot-starter", "mybatis-plus-spring-boot3-starter"},
		"cn.hutool":                {"hutool-all", "hutool-core", "hutool-extra", "hutool-http", "hutool-json", "hutool-log", "hutool-cache", "hutool-poi", "hutool-db", "hutool-crypto", "hutool-captcha", "hutool-jwt", "hutool-setting", "hutool-aop", "hutool-bloomFilter", "hutool-cron", "hutool-dfa", "hutool-script", "hutool-socket", "hutool-system"},
		"io.github.linpeilie":      {"mapstruct-plus", "mapstruct-plus-spring-boot-starter", "mapstruct-plus-processor"},
		"cn.dev33":                 {"sa-token-core", "sa-token-spring-boot3-starter", "sa-token-spring-boot-starter", "sa-token-spring-boot-autoconfig", "sa-token-spring-mvc", "sa-token-spring-aop", "sa-token-redis-jackson", "sa-token-dao-redis-jackson", "sa-token-jwt", "sa-token-jakarta-servlet", "sa-token-servlet"},
	}
	for group, artifacts := range groups {
		for _, artifact := range artifacts {
			result[group+":"+artifact] = true
		}
	}
	return result
}()

type manifestIdentity struct{ coordinate, title, module, class string }

var manifestIdentities = []manifestIdentity{
	{"org.springframework.boot:spring-boot", "Spring Boot", "spring.boot", "org/springframework/boot/SpringApplication.class"},
	{"org.springframework.boot:spring-boot-autoconfigure", "Spring Boot AutoConfigure", "spring.boot.autoconfigure", "org/springframework/boot/autoconfigure/SpringBootApplication.class"},
	{"org.springframework.boot:spring-boot-actuator", "Spring Boot Actuator", "spring.boot.actuator", "org/springframework/boot/actuate/endpoint/EndpointId.class"},
	{"org.springframework.boot:spring-boot-actuator-autoconfigure", "Spring Boot Actuator AutoConfigure", "spring.boot.actuator.autoconfigure", "org/springframework/boot/actuate/autoconfigure/endpoint/EndpointAutoConfiguration.class"},
	{"org.springframework:spring-core", "spring-core", "spring.core", "org/springframework/core/SpringVersion.class"},
	{"org.springframework:spring-beans", "spring-beans", "spring.beans", "org/springframework/beans/factory/BeanFactory.class"},
	{"org.springframework:spring-context", "spring-context", "spring.context", "org/springframework/context/ApplicationContext.class"},
	{"org.springframework:spring-aop", "spring-aop", "spring.aop", "org/springframework/aop/Advisor.class"},
	{"org.springframework:spring-expression", "spring-expression", "spring.expression", "org/springframework/expression/Expression.class"},
	{"org.springframework:spring-web", "spring-web", "spring.web", "org/springframework/web/context/WebApplicationContext.class"},
	{"org.springframework:spring-webmvc", "spring-webmvc", "spring.webmvc", "org/springframework/web/servlet/DispatcherServlet.class"},
	{"org.springframework:spring-webflux", "spring-webflux", "spring.webflux", "org/springframework/web/reactive/DispatcherHandler.class"},
	{"org.springframework:spring-tx", "spring-tx", "spring.tx", "org/springframework/transaction/PlatformTransactionManager.class"},
	{"org.springframework:spring-jdbc", "spring-jdbc", "spring.jdbc", "org/springframework/jdbc/core/JdbcTemplate.class"},
	{"org.springframework:spring-orm", "spring-orm", "spring.orm", "org/springframework/orm/jpa/LocalContainerEntityManagerFactoryBean.class"},
	{"org.springframework:spring-context-support", "spring-context-support", "spring.context.support", "org/springframework/cache/caffeine/CaffeineCache.class"},
	{"org.springframework:spring-messaging", "spring-messaging", "spring.messaging", "org/springframework/messaging/Message.class"},
	{"org.springframework:spring-oxm", "spring-oxm", "spring.oxm", "org/springframework/oxm/Marshaller.class"},
	{"org.springframework:spring-jcl", "spring-jcl", "spring.jcl", "org/apache/commons/logging/LogFactory.class"},
	{"com.baomidou:mybatis-plus-core", "mybatis-plus-core", "com.baomidou.mybatis.plus.core", "com/baomidou/mybatisplus/core/mapper/BaseMapper.class"},
	{"com.baomidou:mybatis-plus-annotation", "mybatis-plus-annotation", "com.baomidou.mybatis.plus.annotation", "com/baomidou/mybatisplus/annotation/TableName.class"},
	{"com.baomidou:mybatis-plus-extension", "mybatis-plus-extension", "com.baomidou.mybatis.plus.extension", "com/baomidou/mybatisplus/extension/service/IService.class"},
}

func (s *archiveScanner) manifest(body []byte, entries map[string]*zip.File, prefix, jarSHA string) error {
	fields := parseManifest(body)
	for _, identity := range manifestIdentities {
		if len(fields["implementation-title"]) != 1 || fields["implementation-title"][0] != identity.title || len(fields["automatic-module-name"]) != 1 || fields["automatic-module-name"][0] != identity.module {
			continue
		}
		version := unique(fields["implementation-version"])
		if len(version) != 1 || !versionValue.MatchString(version[0]) {
			s.diagnostic("ambiguous or unresolved manifest version for " + identity.coordinate + " at " + prefix + "META-INF/MANIFEST.MF")
			continue
		}
		class := entries[identity.class]
		if class == nil {
			s.diagnostic("manifest identity lacks representative class for " + identity.coordinate + " at " + prefix + "META-INF/MANIFEST.MF")
			continue
		}
		if s.remaining < 4 {
			return ErrLimit
		}
		reader, err := class.Open()
		if err != nil {
			return err
		}
		var magic [4]byte
		n, readErr := io.ReadFull(contextReader{s.ctx, reader}, magic[:])
		closeErr := reader.Close()
		s.remaining -= int64(n)
		if closeErr != nil {
			return closeErr
		}
		if readErr != nil || n != 4 || !bytes.Equal(magic[:], []byte{0xca, 0xfe, 0xba, 0xbe}) {
			s.diagnostic("manifest representative class has invalid header for " + identity.coordinate + " at " + prefix + identity.class)
			continue
		}
		s.snapshot.Evidence = append(s.snapshot.Evidence, Evidence{identity.coordinate, version[0], prefix + "META-INF/MANIFEST.MF", "manifest-and-class", jarSHA})
	}
	return nil
}

// Manifest headers are case insensitive. Only the main section applies; named
// entry sections must not override the archive's implementation identity.
func parseManifest(body []byte) map[string][]string {
	fields := map[string][]string{}
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	key, value := "", ""
	flush := func() {
		if key != "" {
			fields[key] = append(fields[key], value)
		}
		key, value = "", ""
	}
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			flush()
			break
		}
		if strings.HasPrefix(line, " ") {
			if key != "" {
				value += line[1:]
			}
			continue
		}
		flush()
		if name, content, ok := strings.Cut(line, ": "); ok {
			key = strings.ToLower(name)
			value = content
		}
	}
	flush()
	return fields
}

func parseProperties(body []byte) (map[string][]string, error) {
	properties := map[string][]string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1024), int(maxMetadataBytes)+1)
	logical := ""
	continued := false
	consume := func(line string) error {
		line = strings.TrimLeft(line, " \t\f")
		if line == "" || line[0] == '#' || line[0] == '!' {
			return nil
		}
		split := len(line)
		escaped := false
		for i, c := range line {
			if !escaped && (c == '=' || c == ':' || c == ' ' || c == '\t' || c == '\f') {
				split = i
				break
			}
			if c == '\\' {
				escaped = !escaped
			} else {
				escaped = false
			}
		}
		key, err := unescapeProperty(line[:split])
		if err != nil {
			return err
		}
		rest := strings.TrimLeft(line[split:], " \t\f")
		if len(rest) > 0 && (rest[0] == '=' || rest[0] == ':') {
			rest = rest[1:]
		}
		rest = strings.TrimLeft(rest, " \t\f")
		value, err := unescapeProperty(rest)
		if err != nil {
			return err
		}
		properties[key] = append(properties[key], value)
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if continued {
			line = strings.TrimLeft(line, " \t\f")
		}
		logical += line
		backslashes := 0
		for i := len(logical) - 1; i >= 0 && logical[i] == '\\'; i-- {
			backslashes++
		}
		continued = backslashes%2 == 1
		if continued {
			logical = logical[:len(logical)-1]
			continue
		}
		if err := consume(logical); err != nil {
			return nil, err
		}
		logical = ""
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if logical != "" {
		if err := consume(logical); err != nil {
			return nil, err
		}
	}
	return properties, nil
}

func unescapeProperty(value string) (string, error) {
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			result.WriteByte(value[i])
			continue
		}
		i++
		if i >= len(value) {
			return "", errors.New("unfinished properties escape")
		}
		switch value[i] {
		case 't':
			result.WriteByte('\t')
		case 'n':
			result.WriteByte('\n')
		case 'r':
			result.WriteByte('\r')
		case 'f':
			result.WriteByte('\f')
		case 'u':
			if i+4 >= len(value) {
				return "", errors.New("unfinished properties Unicode escape")
			}
			point, err := strconv.ParseUint(value[i+1:i+5], 16, 16)
			if err != nil {
				return "", fmt.Errorf("invalid properties Unicode escape: %w", err)
			}
			result.WriteRune(rune(point))
			i += 4
		default:
			result.WriteByte(value[i])
		}
	}
	return result.String(), nil
}
