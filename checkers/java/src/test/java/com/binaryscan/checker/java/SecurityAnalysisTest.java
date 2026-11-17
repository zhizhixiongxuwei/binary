package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Inert source fixtures only: no command, class or payload is executed. */
final class SecurityAnalysisTest {
    @TempDir Path root;
    Models.CheckResponse check(Map<String,String> files,String...rules)throws Exception{
        var inputs=new ArrayList<ProjectAnalyzer.Input>();int i=0;for(var entry:new TreeMap<>(files).entrySet()){var p=root.resolve(Integer.toString(i++));Files.writeString(p,entry.getValue());inputs.add(new ProjectAnalyzer.Input(entry.getKey(),p));}
        return ProjectAnalyzer.analyze("security-fixture",inputs,List.of(rules),new JavaAnalyzer());
    }
    @Test void fixedExecutablePrefixAndNumericFormattingDoNotHideCharacterConstruction()throws Exception{
        var r=check(Map.of("Api.java","""
            import org.springframework.web.bind.annotation.GetMapping;
            import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
            import com.baomidou.mybatisplus.core.mapper.BaseMapper;
            class Api {
             BaseMapper<Object> mapper;
             @GetMapping("/fixed") void fixed(String value)throws Exception{Runtime.getRuntime().exec("fixture-tool --file "+value);}
             @GetMapping("/shell") void shell(String value)throws Exception{Runtime.getRuntime().exec("sh -c "+value);}
             @GetMapping("/numeric") Object numeric(Long id){return mapper.selectList(new QueryWrapper<>().last("limit "+text(id)));}
             String text(Object number){return "%s".formatted(number);}
             @GetMapping("/chars") Object chars(char[] chars){return mapper.selectList(new QueryWrapper<>().last(new String(chars)));}
            }
            """),SecurityAnalysis.WEB_EXEC,"java-sql-injection");
        assertEquals(Set.of(SecurityAnalysis.WEB_EXEC,"java-sql-injection"),r.findings().stream().map(Models.Finding::ruleId).collect(java.util.stream.Collectors.toSet()),r.toString());
        assertEquals(Set.of(7,10),r.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),r.toString());
    }
    @Test void includesMapperFragmentsAcrossResourcesAndRetainsOrigin()throws Exception{
        var r=check(Map.of("Api.java","""
            import org.springframework.web.bind.annotation.GetMapping;
            import org.apache.ibatis.annotations.Param;
            interface Mapper {Object find(@Param("order") String value);}
            class Api {Mapper mapper;@GetMapping("/fixture") Object read(String value){return mapper.find(value);}}
            ""","resources/application/one.xml","<mapper namespace=\"Mapper\"><select id=\"find\">select * from fixture <include refid=\"Fragments.order\"/></select></mapper>",
            "resources/application/two.xml","<mapper namespace=\"Fragments\"><sql id=\"order\">order by ${order}</sql></mapper>"),"java-sql-injection");
        assertEquals(1,r.findings().size(),r.toString());assertEquals("resources/application/two.xml",r.findings().getFirst().path());
    }
    @Test void followsRequestThroughPrivateHelperAndKeepsOrdinaryArgvSafe()throws Exception{
        var r=check(Map.of("Api.java","""
            import org.springframework.web.bind.annotation.GetMapping;
            class Api {
              @GetMapping("/fixture") void request(String input)throws Exception { helper(input); }
              private void helper(String command)throws Exception { Runtime.getRuntime().exec(command); }
              @GetMapping("/fixed-program") void fixedProgram(String file)throws Exception { new ProcessBuilder("fixture-tool","--file",file).start(); }
              void notAnEntry(String value)throws Exception { Runtime.getRuntime().exec(value); }
            }
            """),SecurityAnalysis.WEB_EXEC);
        assertEquals(1,r.findings().size(),r.toString());var f=r.findings().getFirst();assertEquals(4,f.line());assertTrue(((List<?>)f.evidence().get("securityTrace")).size()>=2);assertEquals(false,f.evidence().get("maliciousIntentProven"));
    }
    @Test void earlyReturnBranchCannotLeaveNullFactsForLaterHeapJoins()throws Exception{
        var r=check(Map.of("Api.java","""
          import org.springframework.web.bind.annotation.GetMapping;
          class Api {
           @GetMapping("/fixture") void read(String text,boolean stopped)throws Exception{
            if(stopped){Object temporary=new Object();return;}
            if(text.isEmpty()){Object other=new Object();}
            Runtime.getRuntime().exec(text);
           }
          }
          """),SecurityAnalysis.WEB_EXEC);
        assertEquals(1,r.findings().size(),r.toString());
    }
    @Test void distinguishesExpressionTextFromEvaluationContext()throws Exception{
        var r=check(Map.of("Expressions.java","""
            import org.springframework.web.bind.annotation.GetMapping;
            import org.springframework.expression.spel.standard.SpelExpressionParser;
            import org.springframework.expression.spel.support.StandardEvaluationContext;
            class Expressions {
              @GetMapping("/safe") Object safe(String value){var c=new StandardEvaluationContext();c.setVariable("name",value);return new SpelExpressionParser().parseExpression("#name").getValue(c);}
              @GetMapping("/review") Object review(String code){return new SpelExpressionParser().parseExpression(code).getValue();}
            }
            """),SecurityAnalysis.WEB_EXEC);
        assertEquals(1,r.findings().size(),r.toString());assertEquals(6,r.findings().getFirst().line());
    }
    @Test void correlatesUntrustedClassBytesAndSpringRegistration()throws Exception{
        var r=check(Map.of("Registration.java","""
            import org.springframework.web.bind.annotation.PostMapping;
            import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
            class Loader extends ClassLoader { Class<?> read(byte[] bytes){return defineClass(null,bytes,0,bytes.length);} }
            class Registration {
              RequestMappingHandlerMapping mappings;
              @PostMapping("/fixture") void review(byte[] bytes)throws Exception {Class<?> c=new Loader().read(bytes);mappings.registerMapping(null,c.getDeclaredConstructor().newInstance(),null);}
              void normal(){mappings.registerMapping(null,new SafeHandler(),null);}
            }
            class SafeHandler {String hello(){return "hello";}}
            """),SecurityAnalysis.CLASS_LOAD,SecurityAnalysis.WEB_IMPLANT);
        assertEquals(Set.of(SecurityAnalysis.CLASS_LOAD,SecurityAnalysis.WEB_IMPLANT),r.findings().stream().map(Models.Finding::ruleId).collect(java.util.stream.Collectors.toSet()),r.toString());
        assertEquals(2,r.findings().size(),r.toString());
    }
    @Test void normalUndertowConfigurationIsNotAWebImplant()throws Exception{
        var r=check(Map.of("Config.java","""
            import io.undertow.servlet.api.DeploymentInfo;
            import io.undertow.websockets.jsr.WebSocketDeploymentInfo;
            class Config {void configure(DeploymentInfo d){d.addServletContextAttribute(WebSocketDeploymentInfo.ATTRIBUTE_NAME,new WebSocketDeploymentInfo());}}
            """),SecurityAnalysis.WEB_IMPLANT);
        assertTrue(r.findings().isEmpty(),r.toString());
    }
    @Test void detectsSpecialCredentialBranchButPreservesVerifiedAndConjunctiveChecks()throws Exception{
        var r=check(Map.of("Authentication.java","""
            import org.springframework.web.bind.annotation.PostMapping;
            import cn.hutool.crypto.digest.BCrypt;
            class Authentication {
              @PostMapping("/review") boolean review(String password,String hash){if(password.equals("fixture-override"))return true;return BCrypt.checkpw(password,hash);}
              @PostMapping("/verified") boolean verified(String password,String hash){if(!BCrypt.checkpw(password,hash))throw new IllegalArgumentException();if(password.equals("fixture-override"))return true;return true;}
              @PostMapping("/and") boolean conjunction(String password,String hash){if(BCrypt.checkpw(password,hash)&&password.equals("fixture-override"))return true;return false;}
            }
            """),SecurityAnalysis.AUTH_BYPASS);
        assertEquals(1,r.findings().size(),r.toString());assertEquals(4,r.findings().getFirst().line());
    }
    @Test void jacksonRequiresActualUseAndHonorsDisablingOrRestrictedValidator()throws Exception{
        var r=check(Map.of("Redis.java","""
            import com.fasterxml.jackson.databind.ObjectMapper;
            import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
            import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
            import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
            import org.redisson.codec.TypedJsonJacksonCodec;
            import org.redisson.codec.CompositeCodec;
            import org.redisson.config.Config;
            class Redis {
              void review(Config config){ObjectMapper m=new ObjectMapper();m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,DefaultTyping.NON_FINAL);var codec=new TypedJsonJacksonCodec(Object.class,m);config.setCodec(new CompositeCodec(null,codec,codec));}
              void unused(){ObjectMapper m=new ObjectMapper();m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,DefaultTyping.NON_FINAL);}
              Object disabled(String text)throws Exception{ObjectMapper m=new ObjectMapper();m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,DefaultTyping.NON_FINAL);m.deactivateDefaultTyping();return m.readValue(text,Object.class);}
              Object restricted(String text)throws Exception{ObjectMapper m=new ObjectMapper();m.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().allowIfSubType("example.model.").build(),DefaultTyping.NON_FINAL);return m.readValue(text,Object.class);}
            }
            """),SecurityAnalysis.JACKSON);
        assertEquals(1,r.findings().size(),r.toString());assertEquals(9,r.findings().getFirst().line());assertEquals("configuration-risk",r.findings().getFirst().evidence().get("certainty"));
    }
    @Test void infersImplicitCustomizerLambdaAndChainedConfigurationReceiver()throws Exception{
        var r=check(Map.of("Customizer.java","""
          import org.redisson.config.Config;
          import org.redisson.codec.TypedJsonJacksonCodec;
          import com.fasterxml.jackson.databind.ObjectMapper;
          import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
          import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
          interface Customizer {void customize(Config config);}
          class Setup {Customizer configure(){return config->{ObjectMapper m=new ObjectMapper();m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,DefaultTyping.NON_FINAL);config.setCodec(new TypedJsonJacksonCodec(Object.class,m));};}}
          """),SecurityAnalysis.JACKSON);
        assertEquals(1,r.findings().size(),r.toString());
    }
    @Test void numericHutoolStringConversionCannotHideAStringSqlPath()throws Exception{
        var file=root.resolve("Hutool.java");Files.writeString(file,"""
          import org.springframework.web.bind.annotation.GetMapping;
          import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
          import com.baomidou.mybatisplus.core.mapper.BaseMapper;
          import cn.hutool.core.convert.Convert;
          class Api {
           BaseMapper<Object> mapper;
           String sql(Object value,String column){return "find_in_set('%s',%s)".formatted(Convert.toStr(value),column);}
           @GetMapping("/numeric") Object numeric(Long id){return mapper.selectList(new QueryWrapper<>().apply(sql(id,"ancestors")));}
           @GetMapping("/string") Object string(String id){return mapper.selectList(new QueryWrapper<>().apply(sql(id,"ancestors")));}
          }
          """);
        var r=ProjectAnalyzer.analyze("hutool",List.of(new ProjectAnalyzer.Input("Hutool.java",file)),List.of("java-sql-injection"),new JavaAnalyzer(),new FrameworkContracts(Map.of("cn.hutool:hutool-core","5.8.27")));
        assertEquals(1,r.findings().size(),r.toString());assertEquals(9,r.findings().getFirst().line());
    }
    @Test void jwtResourcesAreParsedWithoutExposingValuesOrConfusingEnvironmentOnlyKeys()throws Exception{
        String secret="fixture-only-signing-key";
        var r=check(Map.of("Jwt.java","""
            import cn.dev33.satoken.jwt.StpLogicJwtForSimple;
            class Jwt {Object logic(){return new StpLogicJwtForSimple();}}
            ""","resources/application/application.yml","sa-token:\n  jwt-secret-key: "+secret+"\n---\njwt:\n  secret: ${JWT_SECRET}\n",
            "resources/application/default.properties","jwt.secret=${JWT_KEY:fixture-fallback}\n"),SecurityAnalysis.JWT);
        assertEquals(2,r.findings().size(),r.toString());for(var f:r.findings()){assertFalse(f.evidence().toString().contains(secret));assertFalse(f.message().contains(secret));assertEquals(true,f.evidence().get("redactSnippet"));assertEquals(1,((List<?>)f.evidence().get("bindingLocations")).size());}
        assertEquals(1,r.coverage().totalFiles());assertEquals(1,r.coverage().parsedFiles());
    }
    @Test void bindsMapperXmlRawSlotsButPreservesHashParameterBinding()throws Exception{
        var r=check(Map.of("Api.java","""
            import org.springframework.web.bind.annotation.GetMapping;
            import org.apache.ibatis.annotations.Param;
            import org.apache.ibatis.annotations.Mapper;
            @Mapper interface Queries {Object raw(@Param("table") String table);Object bound(@Param("name") String name);}
            class Api {Queries mapper;@GetMapping("/fixture") void get(String input){mapper.raw(input);mapper.bound(input);}}
            ""","resources/application/mapper/Queries.xml","<mapper namespace=\"Queries\"><select id=\"raw\">select * from ${table}</select><select id=\"bound\">select * from users where name = #{name}</select></mapper>"),"java-sql-injection");
        assertEquals(1,r.findings().size(),r.toString());assertEquals("resources/application/mapper/Queries.xml",r.findings().getFirst().path());
    }
    @Test void wrapperDataflowRequiresExecutionAndPreservesBoundValuesNumericIdsAndGuards()throws Exception{
        var r=check(Map.of("SqlApi.java","""
            import org.springframework.web.bind.annotation.GetMapping;
            import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
            import com.baomidou.mybatisplus.core.mapper.BaseMapper;
            interface Queries extends BaseMapper<Object> {}
            class SqlApi {
              Queries mapper;
              @GetMapping("/review") void review(String input){QueryWrapper<Object> q=new QueryWrapper<>();q.apply("name = '"+input+"'");mapper.selectList(q);}
              @GetMapping("/bound") void bound(String input){mapper.selectList(new QueryWrapper<>().eq("name",input));}
              @GetMapping("/constant") void constant(String input){mapper.selectList(new QueryWrapper<>().last("limit 1"));}
              @GetMapping("/unused") void unused(String input){new QueryWrapper<>().apply(input);}
              @GetMapping("/numeric") void numeric(Long id){mapper.selectList(new QueryWrapper<>().apply("id = "+id));}
              static String identifier(String value){if(!value.matches("[a-zA-Z0-9_]+"))throw new IllegalArgumentException();return value;}
              @GetMapping("/guarded") void guarded(String name){mapper.selectList(new QueryWrapper<>().orderByAsc(identifier(name)));}
            }
            """),"java-sql-injection");
        assertEquals(1,r.findings().size(),r.toString());assertEquals(7,r.findings().getFirst().line());
    }
    @Test void wrapperAndMapperMutationsSurviveHelperCallsAndAliases()throws Exception{
        var r=check(Map.of("Helpers.java","""
            import org.springframework.web.bind.annotation.GetMapping;
            import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
            import com.baomidou.mybatisplus.core.mapper.BaseMapper;
            interface Queries extends BaseMapper<Object>{}
            class Helpers {
              Queries mapper;
              void append(QueryWrapper<Object> wrapper,String sql){wrapper.apply(sql);}
              void execute(QueryWrapper<Object> wrapper){mapper.selectList(wrapper);}
              @GetMapping("/fixture") void api(String input){QueryWrapper<Object> q=new QueryWrapper<>();QueryWrapper<Object> alias=q;append(alias,input);execute(q);}
            }
            """),"java-sql-injection");
        assertEquals(1,r.findings().size(),r.toString());assertEquals(8,r.findings().getFirst().line());
    }
    @Test void mapperHelperUseAndConditionalDisableKeepTheirActualEffects()throws Exception{
        var r=check(Map.of("MapperHelpers.java","""
            import com.fasterxml.jackson.databind.ObjectMapper;
            import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
            import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
            class MapperHelpers {
              void configure(ObjectMapper m){m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,DefaultTyping.NON_FINAL);}
              void disable(ObjectMapper m){m.deactivateDefaultTyping();}
              void conditional(ObjectMapper m,boolean flag){if(flag)m.deactivateDefaultTyping();}
              Object read(ObjectMapper m,String text)throws Exception{return m.readValue(text,Object.class);}
              Object risk(String text)throws Exception{ObjectMapper m=new ObjectMapper();configure(m);return read(m,text);}
              Object safe(String text)throws Exception{ObjectMapper m=new ObjectMapper();configure(m);disable(m);return read(m,text);}
              Object maybe(String text,boolean flag)throws Exception{ObjectMapper m=new ObjectMapper();configure(m);conditional(m,flag);return read(m,text);}
            }
            """),SecurityAnalysis.JACKSON);
        assertEquals(1,r.findings().size(),r.toString());assertEquals(8,r.findings().getFirst().line());
        // Same decoder location is deduplicated, but the unconditional safe
        // caller must not manufacture a broad-typing report by itself.
        var safe=check(Map.of("Safe.java","""
            import com.fasterxml.jackson.databind.ObjectMapper;
            import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
            import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
            class Safe {void disable(ObjectMapper m){m.deactivateDefaultTyping();}Object read(ObjectMapper m,String s)throws Exception{return m.readValue(s,Object.class);}Object run(String text)throws Exception{ObjectMapper m=new ObjectMapper();m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,DefaultTyping.NON_FINAL);disable(m);return read(m,text);}}
            """),SecurityAnalysis.JACKSON);
        assertTrue(safe.findings().isEmpty(),safe.toString());
    }
    @Test void constantResolvedReflectionDoesNotHideUntrustedClassDefinition()throws Exception{
        var r=check(Map.of("Reflective.java","""
            import org.springframework.web.bind.annotation.PostMapping;
            class Reflective { @PostMapping("/fixture") Object api(byte[] bytes)throws Exception {var method=ClassLoader.class.getDeclaredMethod("defineClass",byte[].class,int.class,int.class);return method.invoke(getClass().getClassLoader(),bytes,0,bytes.length);}}
            """),SecurityAnalysis.CLASS_LOAD);
        assertEquals(1,r.findings().size(),r.toString());
    }
}
