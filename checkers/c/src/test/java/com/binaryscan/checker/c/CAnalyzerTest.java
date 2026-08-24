package com.binaryscan.checker.c;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

final class CAnalyzerTest {
    @Test
    void convertsAntlrCodePointColumnToMonacoUtf16Column() {
        String content = "const char *label = \"😀中文\"; gets(buffer);";
        var findings = new CAnalyzer().analyze(new Models.SourceFile("unicode.c", content));

        var finding = findings.stream()
            .filter(value -> value.ruleId().equals("cwe-242-gets"))
            .findFirst().orElseThrow();
        assertEquals(1, finding.line());
        assertEquals(content.indexOf("gets") + 1, finding.column());
        assertEquals(29, finding.column());
    }

    @Test
    void restoresAllFifteenBinaryNewRuleFamilies() {
        String content = """
            int sample(char *cmd, char *fmt, char *p) {
              char buf[4];
              char local;
              char *wrong = malloc(sizeof(wrong));
              int z = 1 / 0;
              gets(buf);
              strcpy(buf, p);
              scanf("%s", buf);
              printf(fmt);
              system(cmd);
              buf[4] = 1;
              z = buf[5];
              free(&local);
              free(p + 1);
              tmpnam(buf);
              read(0, buf, 4);
              MD5_Init(p);
              chmod("file", 0777);
              return &local;
            }
            """;

        Set<String> actual = new CAnalyzer().analyze(new Models.SourceFile("rules.c", content)).stream()
            .map(Models.Finding::ruleId).collect(Collectors.toSet());

        assertEquals(CAnalyzer.RULE_IDS, actual);
    }

    @Test
    void ignoresRuleNamesInsideCommentsAndStringLiterals() {
        String content = """
            void safe(void) {
              // gets(buffer); system(command);
              const char *text = "strcpy(buffer, source)";
            }
            """;

        assertEquals(0, new CAnalyzer().analyze(new Models.SourceFile("safe.c", content)).size());
    }

    @Test
    void ignoresGhidraExternalThunkDefinitionHeaders() {
        String content = """
            int _system(char *param_1) {
              return (*(code *)PTR__system_100001018)();
            }
            """;

        assertEquals(0, new CAnalyzer().analyze(new Models.SourceFile("thunk.c", content)).stream()
            .filter(finding -> finding.ruleId().equals("cwe-78-command"))
            .count());
    }

    @Test
    void distinguishesOutOfBoundsReadsFromWrites() {
        String content = """
            int sample(void) {
              int source[4];
              int target[4];
              target[source[4]] = 0;
              return target[0];
            }
            """;
        Set<String> actual = new CAnalyzer().analyze(new Models.SourceFile("bounds.c", content)).stream()
            .map(Models.Finding::ruleId).collect(Collectors.toSet());

        assertEquals(Set.of("cwe-125-oob-read"), actual);
        assertFalse(actual.contains("cwe-787-oob-write"));
    }

    @Test
    void evaluatesPointerStateAtEachFreeCall() {
        String beforeIncrement = """
            void sample(char *p) {
              free(p);
              p++;
            }
            """;
        String afterIncrement = """
            void sample(char *p) {
              p++;
              *p = 0;
              free(p);
            }
            """;
        String stackPointer = """
            void sample(void) {
              int local;
              int *p = &local;
              *p = 0;
              free(p);
              p = malloc(8);
              free(p);
            }
            """;

        assertFalse(ruleIds(beforeIncrement).contains("cwe-761-offset-free"));
        assertEquals(Set.of("cwe-761-offset-free"), intersection(
            ruleIds(afterIncrement), Set.of("cwe-761-offset-free")));
        assertEquals(Set.of("cwe-590-invalid-free"), intersection(
            ruleIds(stackPointer), Set.of("cwe-590-invalid-free")));
    }

    private static Set<String> ruleIds(String content) {
        return new CAnalyzer().analyze(new Models.SourceFile("pointer.c", content)).stream()
            .map(Models.Finding::ruleId).collect(Collectors.toSet());
    }

    private static Set<String> intersection(Set<String> values, Set<String> expected) {
        var result = new java.util.HashSet<>(values);
        result.retainAll(expected);
        return result;
    }
}
