package com.binaryscan.checker.java;

import org.w3c.dom.*;
import org.w3c.dom.Node;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.nodes.*;
import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;

/** Parses inert, hash-pinned resources; never resolves XML entities or YAML types. */
final class SecurityResources {
    record Location(String path,int line,int column,String kind,String message) {
        Map<String,Object> evidence(){return Map.of("path",path,"line",line,"column",column,"kind",kind,"message",message);}
    }
    record SqlSlot(String expression,Location location) {}
    final Map<String,List<SqlSlot>> sql=new LinkedHashMap<>();
    final List<Location> jwtKeys=new ArrayList<>();
    final List<Models.Diagnostic> diagnostics=new ArrayList<>();
    record MapperDocument(String path,String text,Element root,String namespace) {}
    record Fragment(MapperDocument document,Element element) {}
    final List<MapperDocument> mapperDocuments=new ArrayList<>();
    static final Pattern SLOT=Pattern.compile("\\$\\{([^}]{1,512})}");
    static SecurityResources read(List<ProjectAnalyzer.Input> resources) throws IOException {
        var out=new SecurityResources();
        for(var file:resources){String text=Files.readString(file.file());String lower=file.path().toLowerCase(Locale.ROOT);
            if((lower.endsWith(".jsp")||lower.endsWith(".jspx"))&&(text.contains("<%")||text.contains(":scriptlet")))out.diagnostics.add(new Models.Diagnostic("JAVA_JSP_SCRIPTLET_UNSUPPORTED",file.path(),1,1,"JSP scriptlet is retained as a resource; Java source dataflow does not analyze the generated servlet body"));
            try {
                if(lower.endsWith(".xml"))out.xml(file.path(),text);
                if(lower.endsWith(".yml")||lower.endsWith(".yaml"))out.yaml(file.path(),text);
                if(lower.endsWith(".properties"))out.properties(file.path(),text);
            }catch(Exception invalid){out.diagnostics.add(new Models.Diagnostic("JAVA_RESOURCE_PARSE_ERROR",file.path(),1,1,"resource could not be parsed safely; related configuration/SQL analysis is incomplete"));}
        }out.finishSql();return out;
    }
    private void properties(String path,String text)throws IOException{
        var p=new Properties();p.load(new StringReader(text));
        for(String key:p.stringPropertyNames())if(jwtProperty(key)&&literalSecret(p.getProperty(key)))
            jwtKeys.add(new Location(path,lineOf(text,key),1,"configuration","packaged JWT signing key is a non-empty literal or has a literal fallback; value redacted"));
    }
    private void yaml(String path,String text){
        var options=new LoaderOptions();options.setMaxAliasesForCollections(20);options.setCodePointLimit(1<<20);options.setNestingDepthLimit(64);
        var yaml=new Yaml(new SafeConstructor(options));
        for(org.yaml.snakeyaml.nodes.Node node:yaml.composeAll(new StringReader(text)))walkYaml(path,node,"",Collections.newSetFromMap(new IdentityHashMap<>()),0);
    }
    private void walkYaml(String path,org.yaml.snakeyaml.nodes.Node node,String prefix,Set<org.yaml.snakeyaml.nodes.Node> seen,int depth){
        if(node==null||depth>64||!seen.add(node))return;
        if(node instanceof MappingNode mapping)for(var tuple:mapping.getValue())if(tuple.getKeyNode() instanceof ScalarNode key){
            String property=prefix.isEmpty()?key.getValue():prefix+"."+key.getValue();org.yaml.snakeyaml.nodes.Node value=tuple.getValueNode();
            if(jwtProperty(property)&&value instanceof ScalarNode scalar&&Set.of(Tag.STR,Tag.INT,Tag.FLOAT,Tag.BOOL).contains(scalar.getTag())&&literalSecret(scalar.getValue()))
                jwtKeys.add(new Location(path,scalar.getStartMark()==null?1:scalar.getStartMark().getLine()+1,1,"configuration","packaged JWT signing key is a non-empty literal or has a literal fallback; value redacted"));
            walkYaml(path,value,property,seen,depth+1);
        }
    }
    static boolean jwtProperty(String key){String value=key.toLowerCase(Locale.ROOT).replace('_','-');return value.equals("sa-token.jwt-secret-key")||value.endsWith(".jwt.secret")||value.endsWith(".jwt.secret-key")||value.equals("jwt.secret")||value.equals("jwt.secret-key")||value.equals("jwt.signing-key");}
    static boolean literalSecret(String value){if(value==null||value.isBlank())return false;String v=value.trim();if(v.startsWith("${")&&v.endsWith("}")){int colon=v.indexOf(':');return colon>2&&colon<v.length()-2;}return !v.contains("${");}
    private void xml(String path,String text)throws Exception{
        // Mapper DOCTYPE declarations are common. Remove the declaration without
        // loading its DTD; every external resolver and entity remains disabled.
        String inert=text.replaceAll("(?s)<!DOCTYPE[^>\\[]*(?:\\[[\\s\\S]*?]\\s*)?>","");
        var f=DocumentBuilderFactory.newInstance();f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);f.setFeature("http://xml.org/sax/features/external-general-entities",false);f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");f.setXIncludeAware(false);f.setExpandEntityReferences(false);
        var builder=f.newDocumentBuilder();builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());var doc=builder.parse(new InputSource(new StringReader(inert)));Element root=doc.getDocumentElement();if(!root.getTagName().equals("mapper"))return;
        String namespace=root.getAttribute("namespace");if(!namespace.isBlank())mapperDocuments.add(new MapperDocument(path,text,root,namespace));
    }
    private void finishSql(){
        var fragments=new LinkedHashMap<String,Fragment>();var ambiguous=new HashSet<String>();for(var doc:mapperDocuments){var all=doc.root.getElementsByTagName("sql");for(int i=0;i<all.getLength();i++){var element=(Element)all.item(i);String key=doc.namespace+"."+element.getAttribute("id");if(ambiguous.contains(key))continue;if(fragments.putIfAbsent(key,new Fragment(doc,element))!=null){fragments.remove(key);ambiguous.add(key);diagnostics.add(new Models.Diagnostic("JAVA_SQL_FRAGMENT_AMBIGUOUS",doc.path,1,1,"multiple SQL fragments have the same namespace and id"));}}}
        for(var doc:mapperDocuments)for(String tag:List.of("select","insert","update","delete")){var statements=doc.root.getElementsByTagName(tag);for(int i=0;i<statements.getLength();i++){
            var element=(Element)statements.item(i);var slots=new ArrayList<SqlSlot>();collectSlots(element,doc,elementOffset(doc,element),fragments,new HashSet<>(),0,slots);sql.computeIfAbsent(doc.namespace+"#"+element.getAttribute("id"),ignored->new ArrayList<>()).addAll(slots);
        }}
    }
    private void collectSlots(Node node,MapperDocument doc,int start,Map<String,Fragment> fragments,Set<String> visiting,int depth,List<SqlSlot> slots){
        if(depth>32){diagnostics.add(new Models.Diagnostic("JAVA_SQL_INCLUDE_LIMIT",doc.path,1,1,"SQL include nesting exceeds thirty-two levels"));return;}
        if(node instanceof Element element&&element.getTagName().equals("include")){
            String id=element.getAttribute("refid");if(!id.contains("."))id=doc.namespace+"."+id;var target=fragments.get(id);
            if(target==null||!visiting.add(id)){diagnostics.add(new Models.Diagnostic("JAVA_SQL_INCLUDE_UNRESOLVED",doc.path,1,1,"SQL include is missing, dynamic or recursive; its substitutions could not be analyzed"));return;}
            collectSlots(target.element,target.document,elementOffset(target.document,target.element),fragments,visiting,depth+1,slots);visiting.remove(id);return;
        }
        if(node.getNodeType()==Node.TEXT_NODE||node.getNodeType()==Node.CDATA_SECTION_NODE){var matcher=SLOT.matcher(node.getNodeValue());while(matcher.find()){
            String expression=matcher.group(1).strip();int offset=doc.text.indexOf(matcher.group(),Math.max(0,start));if(offset<0)offset=Math.max(0,start);int line=1+(int)doc.text.substring(0,offset).chars().filter(c->c=='\n').count();slots.add(new SqlSlot(expression,new Location(doc.path,line,1,"sql-template","raw MyBatis substitution: ${"+expression+"}")));
        }return;}
        for(Node child=node.getFirstChild();child!=null;child=child.getNextSibling())collectSlots(child,doc,start,fragments,visiting,depth+1,slots);
    }
    private static int elementOffset(MapperDocument doc,Element element){String id=element.getAttribute("id");var pattern=Pattern.compile("<"+Pattern.quote(element.getTagName())+"\\b[^>]*\\bid\\s*=\\s*[\"']"+Pattern.quote(id)+"[\"']");var match=pattern.matcher(doc.text);return match.find()?match.start():0;
    }
    static int lineOf(String text,String token){int index=text.indexOf(token);return index<0?1:1+(int)text.substring(0,index).chars().filter(c->c=='\n').count();}
}
