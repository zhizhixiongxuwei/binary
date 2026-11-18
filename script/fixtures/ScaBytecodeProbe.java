import java.nio.file.*;
import org.springframework.asm.*;
public class ScaBytecodeProbe {
    public static void main(String[] args) throws Exception {
        for (String name : new String[]{"Reachable","Unreachable","Reflective"}) {
            int[] counts = new int[2];
            new ClassReader(Files.readAllBytes(Path.of(args[0], name+".class"))).accept(new ClassVisitor(Opcodes.ASM9) {
                public MethodVisitor visitMethod(int access,String method,String descriptor,String signature,String[] exceptions) {
                    if(method.equals("main")) return new MethodVisitor(Opcodes.ASM9) {
                        public void visitMethodInsn(int op,String owner,String target,String desc,boolean itf) {
                            if(owner.startsWith("org/apache/commons/text/")) counts[0]++;
                            if(owner.equals("java/lang/Class")) counts[1]++;
                        }
                    };
                    return null;
                }
            },ClassReader.SKIP_FRAMES);
            System.out.println(name+": entryTextCalls="+counts[0]+", reflection="+counts[1]);
            if(name.equals("Reachable") && counts[0]==0 || name.equals("Unreachable") && counts[0]!=0 || name.equals("Reflective") && counts[1]==0) throw new AssertionError(name);
        }
    }
}
