lexer grammar PseudoCLexer;

LineComment : '//' ~[\r\n]* -> skip ;
BlockComment : '/*' .*? '*/' -> skip ;
Identifier : [a-zA-Z_] [a-zA-Z_0-9]* ;
StringLiteral : '"' ( '\\' . | ~["\\] )* '"' ;
CharacterLiteral : '\'' ( '\\' . | ~['\\] )* '\'' ;
Number : [0-9] [a-zA-Z_0-9.]* ;
Whitespace : [ \t\r\n]+ -> skip ;
Symbol : . ;
