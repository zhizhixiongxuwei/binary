package com.binaryscan.checker.java;

import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import java.util.*;
import static com.binaryscan.checker.java.NullDereferenceAnalyzer.*;

/** Conditional Bean Validation facts. Unchecked Java calls keep their own context. */
final class ValidationContexts {
    private static final String DEFAULT="jakarta.validation.groups.Default";
    record Property(String type,Set<String> groups,boolean cascade) {}
    final Map<String,Map<String,Property>> properties=new HashMap<>();
    final Map<String,Set<String>> identities=new HashMap<>();
    private final ProjectContext project;
    ValidationContexts(ProjectContext project){this.project=project;}
    void index(TypeDeclaration<?> declaration,ProjectContext.TypeInfo owner){
        var values=new LinkedHashMap<String,Property>();
        // Group sequences/conversions and custom constraints require provider
        // semantics; do not infer a non-null fact from those declarations.
        if(declaration.findAll(AnnotationExpr.class).stream().anyMatch(a->Set.of("GroupSequence","ConvertGroup","List").contains(a.getName().getIdentifier())))return;
        for(var field:declaration.getFields())for(var variable:field.getVariables()){
            Set<String> groups=new HashSet<>();boolean cascade=false;
            for(var annotation:field.getAnnotations()){
                String name=project.qualify(annotation.getNameAsString(),owner);
                if(Set.of("jakarta.validation.constraints.NotNull","jakarta.validation.constraints.NotBlank","jakarta.validation.constraints.NotEmpty","javax.validation.constraints.NotNull","javax.validation.constraints.NotBlank","javax.validation.constraints.NotEmpty").contains(name))groups.addAll(groups(annotation,owner));
                cascade|=Set.of("jakarta.validation.Valid","javax.validation.Valid").contains(name);
            }
            if(!groups.isEmpty()||cascade)values.put(variable.getNameAsString(),new Property(project.qualifyType(variable.getTypeAsString(),owner),Set.copyOf(groups),cascade));
        }
        properties.put(owner.name,values);
    }
    Set<String> groups(AnnotationExpr annotation,ProjectContext.TypeInfo owner){
        Expression value=null;
        if(annotation instanceof SingleMemberAnnotationExpr single)value=single.getMemberValue();
        if(annotation instanceof NormalAnnotationExpr normal)for(var pair:normal.getPairs())if(pair.getNameAsString().equals("groups")||pair.getNameAsString().equals("value"))value=pair.getValue();
        if(value==null)return Set.of(DEFAULT);
        var result=new TreeSet<String>();for(var literal:value.findAll(ClassExpr.class))result.add(project.qualify(literal.getTypeAsString(),owner));
        return result.isEmpty()?Set.of(DEFAULT):Set.copyOf(result);
    }
    Value validated(Value value,Set<String> groups){
        if(value.type()==null)return value;
        String id="validated:"+String.join(",",new TreeSet<>(groups));identities.put(id,Set.copyOf(groups));
        return new Value(value.type(),value.nullness(),value.trace(),value.parameter(),id,value.booleanValue());
    }
    Value property(Value receiver,String field,String path,com.github.javaparser.ast.Node site){
        var active=identities.get(receiver.objectId());if(active==null||receiver.type()==null)return null;
        var values=properties.get(project.qualify(receiver.type().asString(),null));if(values==null)return null;
        var property=values.get(field);if(property==null)return null;
        var declared=project.field(project.types.get(project.qualify(receiver.type().asString(),null)),field);
        Nullness state=property.groups.stream().anyMatch(active::contains)?Nullness.NON_NULL:declared==null?Nullness.UNKNOWN:declared.state();
        if(state==Nullness.NON_NULL)project.proof(path,site,"bean-validation-conditional-property","successful validation of the same object and matching groups constrains "+field+"; unchecked calls retain a separate context");
        Value result=new Value(SourceParsing.type(property.type),state);
        return property.cascade?validated(result,active):state==Nullness.NON_NULL?result:null;
    }
    void entries(MethodDeclaration method,ProjectContext.MethodInfo info,TypeDeclaration<?> owner){
        if(!project.contracts.supports("org.springframework:spring-webmvc")||!owner.getAnnotations().stream().anyMatch(a->Set.of("org.springframework.web.bind.annotation.RestController","org.springframework.stereotype.Controller").contains(project.qualify(a.getNameAsString(),info.owner))))return;
        boolean mapped=method.getAnnotations().stream().anyMatch(a->project.qualify(a.getNameAsString(),info.owner).startsWith("org.springframework.web.bind.annotation.")&&a.getName().getIdentifier().endsWith("Mapping"));
        if(!mapped||method.getParameters().stream().anyMatch(p->Set.of("org.springframework.validation.Errors","org.springframework.validation.BindingResult").contains(project.qualify(p.getTypeAsString(),info.owner))))return;
        var inputs=new Value[info.parameters.size()];Arrays.fill(inputs,UNKNOWN);boolean constrained=false;
        for(int i=0;i<inputs.length;i++){
            var parameter=method.getParameter(i);
            var validation=parameter.getAnnotations().stream().filter(a->Set.of("jakarta.validation.Valid","javax.validation.Valid","org.springframework.validation.annotation.Validated").contains(project.qualify(a.getNameAsString(),info.owner))).findFirst();
            boolean body=parameter.getAnnotations().stream().anyMatch(a->Set.of("org.springframework.web.bind.annotation.RequestBody","org.springframework.web.bind.annotation.RequestPart","org.springframework.web.bind.annotation.ModelAttribute").contains(project.qualify(a.getNameAsString(),info.owner)));
            if(validation.isPresent()&&body){inputs[i]=validated(new Value(SourceParsing.type(project.qualifyType(parameter.getTypeAsString(),info.owner)),Nullness.UNKNOWN),groups(validation.get(),info.owner));constrained=true;}
        }
        if(constrained)info.variants.put("HTTP_VALIDATED",new ProjectContext.Variant("HTTP_VALIDATED",inputs));
    }
}
