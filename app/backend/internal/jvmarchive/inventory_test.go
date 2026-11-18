package jvmarchive
import("context";"os";"testing";"strings")
func TestSCAArchiveLayouts(t *testing.T){
 for _,name:=range []string{"reachable-plain.jar","reachable-boot.jar","reachable-war.war"}{t.Run(name,func(t *testing.T){p:="../../../../test-fixtures/sca/"+name;if _,e:=os.Stat(p);e!=nil{t.Skip("generate SCA fixtures")};d,e:=Inventory(context.Background(),p,name);if e!=nil{t.Fatal(e)};n:=0;for _,c:=range d.Components{if c.PURL=="pkg:maven/org.apache.commons/commons-text@1.9"{n++;if !strings.Contains(c.Path,"commons-text-1.9.jar"){t.Fatal(c)}}};if n!=1{t.Fatalf("expected exact text instance: %+v",d.Components)}})}
}
