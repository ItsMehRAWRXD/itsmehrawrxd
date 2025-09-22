import java.io.*;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Enhanced EON Compiler v2.0 - Java Implementation
 * Based on comprehensive features from rwararw.txt specification
 */
public class EonCompilerEnhanced {
    
    // Token types
    public enum TokenType {
        // Basic tokens
        EOF, IDENTIFIER, NUMBER, STRING, CHAR,
        
        // Keywords
        DEF, MODEL, FUNC, LOOP, IF, ELSE, LET, CONST, RET, BREAK, CONTINUE,
        IMPORT, EXPORT, MATCH, CASE, DEFAULT, TRY, CATCH, FINALLY, THROW,
        
        // Type keywords
        INT, FLOAT, BOOL, VOID, AUTO,
        
        // Operators
        PLUS, MINUS, MULTIPLY, DIVIDE, MODULO, POWER, ASSIGN, PLUS_ASSIGN,
        MINUS_ASSIGN, MULTIPLY_ASSIGN, DIVIDE_ASSIGN, EQUALS, NOT_EQUALS,
        GREATER, GREATER_EQUAL, LESS, LESS_EQUAL, LOGICAL_AND, LOGICAL_OR,
        LOGICAL_NOT, BITWISE_AND, BITWISE_OR, BITWISE_XOR, BITWISE_NOT,
        LEFT_SHIFT, RIGHT_SHIFT,
        
        // Punctuation
        LPAREN, RPAREN, LBRACE, RBRACE, LBRACKET, RBRACKET, SEMICOLON,
        COMMA, DOT, COLON, DOUBLE_COLON, ARROW, FAT_ARROW, QUESTION,
        AMPERSAND, STAR,
        
        // Special
        NEWLINE, INDENT, DEDENT,
        
        // Memory management
        ALLOC, FREE, SIZEOF,
        
        // Concurrency
        SPAWN, SHARED, MUTEX, LOCK, UNLOCK
    }
    
    // Token class
    public static class Token {
        public TokenType type;
        public String value;
        public int line;
        public int column;
        
        public Token(TokenType type, String value, int line, int column) {
            this.type = type;
            this.value = value;
            this.line = line;
            this.column = column;
        }
        
        @Override
        public String toString() {
            return String.format("Token(%s, '%s', %d:%d)", type, value, line, column);
        }
    }
    
    // AST Node types
    public enum AstType {
        NUMBER, STRING, CHAR, OP, IDENTIFIER, VAR_DECL, ASSIGN, IF, ELSE, RET,
        BLOCK, FUNCTION_DEFINITION, FUNCTION_CALL, STRUCT_DEFINITION, POINTER_TYPE,
        DEREFERENCE, ADDRESS_OF, PARAMETER, STRUCT_FIELD, PROGRAM, ALLOC, FREE,
        SIZEOF, FUNCTION_PROTOTYPE, SPAWN, ASSIGN_DEREF, WHILE_LOOP, FOR_LOOP,
        BREAK, CONTINUE, MATCH, CASE, TRY, CATCH, FINALLY, THROW, MEMBER_ACCESS,
        ARRAY_ACCESS, IMPORT, EXPORT, MUTEX, LOCK, UNLOCK
    }
    
    // AST Node class
    public static class AstNode {
        public AstType type;
        public int value;
        public String name;
        public int op;
        public AstNode left, right, cond, body, next, args, params, fields;
        public int line, column;
        
        // Union-like data for different node types
        public String varName;
        public AstNode initExpr;
        public String funcName;
        public AstNode funcParams, funcBody;
        public AstNode funcArgs;
        public String structName;
        public AstNode structFields;
        public AstNode structure, member;
        public AstNode array, index;
        public AstNode forInit, forCond, forIncr, forBody;
        public AstNode whileCond, whileBody;
        public AstNode tryBlock, catchBlock, finallyBlock;
        
        public AstNode(AstType type, int line, int column) {
            this.type = type;
            this.line = line;
            this.column = column;
        }
    }
    
    // Symbol class
    public static class Symbol {
        public String name;
        public String type;
        public int stackOffset;
        public boolean isFunction;
        public boolean isParameter;
        public boolean isShared;
        
        public Symbol(String name, String type) {
            this.name = name;
            this.type = type;
            this.isFunction = false;
            this.isParameter = false;
            this.isShared = false;
        }
    }
    
    // Scope class
    public static class Scope {
        public Map<String, Symbol> symbols = new HashMap<>();
        public Scope parent;
        public int level;
        
        public Scope(Scope parent) {
            this.parent = parent;
            this.level = parent != null ? parent.level + 1 : 0;
        }
    }
    
    // Compiler state
    private String source;
    private int pos;
    private int line;
    private int column;
    private Token currentToken;
    private Scope currentScope;
    private Scope globalScope;
    private int tempVarCount;
    private int labelCount;
    
    // Keyword mapping
    private static final Map<String, TokenType> KEYWORDS = new HashMap<>();
    static {
        KEYWORDS.put("def", TokenType.DEF);
        KEYWORDS.put("model", TokenType.MODEL);
        KEYWORDS.put("func", TokenType.FUNC);
        KEYWORDS.put("loop", TokenType.LOOP);
        KEYWORDS.put("if", TokenType.IF);
        KEYWORDS.put("else", TokenType.ELSE);
        KEYWORDS.put("let", TokenType.LET);
        KEYWORDS.put("const", TokenType.CONST);
        KEYWORDS.put("ret", TokenType.RET);
        KEYWORDS.put("break", TokenType.BREAK);
        KEYWORDS.put("continue", TokenType.CONTINUE);
        KEYWORDS.put("import", TokenType.IMPORT);
        KEYWORDS.put("export", TokenType.EXPORT);
        KEYWORDS.put("match", TokenType.MATCH);
        KEYWORDS.put("case", TokenType.CASE);
        KEYWORDS.put("default", TokenType.DEFAULT);
        KEYWORDS.put("try", TokenType.TRY);
        KEYWORDS.put("catch", TokenType.CATCH);
        KEYWORDS.put("finally", TokenType.FINALLY);
        KEYWORDS.put("throw", TokenType.THROW);
        KEYWORDS.put("int", TokenType.INT);
        KEYWORDS.put("float", TokenType.FLOAT);
        KEYWORDS.put("bool", TokenType.BOOL);
        KEYWORDS.put("void", TokenType.VOID);
        KEYWORDS.put("auto", TokenType.AUTO);
        KEYWORDS.put("alloc", TokenType.ALLOC);
        KEYWORDS.put("free", TokenType.FREE);
        KEYWORDS.put("sizeof", TokenType.SIZEOF);
        KEYWORDS.put("spawn", TokenType.SPAWN);
        KEYWORDS.put("shared", TokenType.SHARED);
        KEYWORDS.put("mutex", TokenType.MUTEX);
        KEYWORDS.put("lock", TokenType.LOCK);
        KEYWORDS.put("unlock", TokenType.UNLOCK);
    }
    
    public EonCompilerEnhanced(String source) {
        this.source = source;
        this.pos = 0;
        this.line = 1;
        this.column = 1;
        this.tempVarCount = 0;
        this.labelCount = 0;
        this.globalScope = new Scope(null);
        this.currentScope = globalScope;
    }
    
    // Lexer methods
    private void skipWhitespace() {
        while (pos < source.length() && Character.isWhitespace(source.charAt(pos))) {
            if (source.charAt(pos) == '\n') {
                line++;
                column = 1;
            } else {
                column++;
            }
            pos++;
        }
    }
    
    private Token nextToken() {
        skipWhitespace();
        
        if (pos >= source.length()) {
            return new Token(TokenType.EOF, "", line, column);
        }
        
        char c = source.charAt(pos);
        int startLine = line;
        int startColumn = column;
        
        // Identifiers and keywords
        if (Character.isLetter(c) || c == '_') {
            StringBuilder sb = new StringBuilder();
            while (pos < source.length() && (Character.isLetterOrDigit(source.charAt(pos)) || source.charAt(pos) == '_')) {
                sb.append(source.charAt(pos));
                pos++;
                column++;
            }
            String word = sb.toString();
            TokenType keyword = KEYWORDS.get(word);
            if (keyword != null) {
                return new Token(keyword, word, startLine, startColumn);
            } else {
                return new Token(TokenType.IDENTIFIER, word, startLine, startColumn);
            }
        }
        
        // Numbers
        if (Character.isDigit(c)) {
            StringBuilder sb = new StringBuilder();
            while (pos < source.length() && (Character.isDigit(source.charAt(pos)) || source.charAt(pos) == '.')) {
                sb.append(source.charAt(pos));
                pos++;
                column++;
            }
            return new Token(TokenType.NUMBER, sb.toString(), startLine, startColumn);
        }
        
        // Strings
        if (c == '"') {
            pos++;
            column++;
            StringBuilder sb = new StringBuilder();
            while (pos < source.length() && source.charAt(pos) != '"') {
                sb.append(source.charAt(pos));
                pos++;
                column++;
            }
            if (pos < source.length()) {
                pos++;
                column++;
            }
            return new Token(TokenType.STRING, sb.toString(), startLine, startColumn);
        }
        
        // Characters
        if (c == '\'') {
            pos++;
            column++;
            char charValue = pos < source.length() ? source.charAt(pos) : '\0';
            pos++;
            column++;
            if (pos < source.length() && source.charAt(pos) == '\'') {
                pos++;
                column++;
            }
            return new Token(TokenType.CHAR, String.valueOf(charValue), startLine, startColumn);
        }
        
        // Operators and punctuation
        switch (c) {
            case '+':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '=') {
                    pos++;
                    column++;
                    return new Token(TokenType.PLUS_ASSIGN, "+=", startLine, startColumn);
                }
                return new Token(TokenType.PLUS, "+", startLine, startColumn);
                
            case '-':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '>') {
                    pos++;
                    column++;
                    return new Token(TokenType.ARROW, "->", startLine, startColumn);
                } else if (pos < source.length() && source.charAt(pos) == '=') {
                    pos++;
                    column++;
                    return new Token(TokenType.MINUS_ASSIGN, "-=", startLine, startColumn);
                }
                return new Token(TokenType.MINUS, "-", startLine, startColumn);
                
            case '*':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '=') {
                    pos++;
                    column++;
                    return new Token(TokenType.MULTIPLY_ASSIGN, "*=", startLine, startColumn);
                }
                return new Token(TokenType.STAR, "*", startLine, startColumn);
                
            case '/':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '=') {
                    pos++;
                    column++;
                    return new Token(TokenType.DIVIDE_ASSIGN, "/=", startLine, startColumn);
                }
                return new Token(TokenType.DIVIDE, "/", startLine, startColumn);
                
            case '%':
                pos++;
                column++;
                return new Token(TokenType.MODULO, "%", startLine, startColumn);
                
            case '^':
                pos++;
                column++;
                return new Token(TokenType.POWER, "^", startLine, startColumn);
                
            case '=':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '=') {
                    pos++;
                    column++;
                    return new Token(TokenType.EQUALS, "==", startLine, startColumn);
                }
                return new Token(TokenType.ASSIGN, "=", startLine, startColumn);
                
            case '!':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '=') {
                    pos++;
                    column++;
                    return new Token(TokenType.NOT_EQUALS, "!=", startLine, startColumn);
                }
                return new Token(TokenType.LOGICAL_NOT, "!", startLine, startColumn);
                
            case '>':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '=') {
                    pos++;
                    column++;
                    return new Token(TokenType.GREATER_EQUAL, ">=", startLine, startColumn);
                } else if (pos < source.length() && source.charAt(pos) == '>') {
                    pos++;
                    column++;
                    return new Token(TokenType.RIGHT_SHIFT, ">>", startLine, startColumn);
                }
                return new Token(TokenType.GREATER, ">", startLine, startColumn);
                
            case '<':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '=') {
                    pos++;
                    column++;
                    return new Token(TokenType.LESS_EQUAL, "<=", startLine, startColumn);
                } else if (pos < source.length() && source.charAt(pos) == '<') {
                    pos++;
                    column++;
                    return new Token(TokenType.LEFT_SHIFT, "<<", startLine, startColumn);
                }
                return new Token(TokenType.LESS, "<", startLine, startColumn);
                
            case '&':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '&') {
                    pos++;
                    column++;
                    return new Token(TokenType.LOGICAL_AND, "&&", startLine, startColumn);
                }
                return new Token(TokenType.AMPERSAND, "&", startLine, startColumn);
                
            case '|':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == '|') {
                    pos++;
                    column++;
                    return new Token(TokenType.LOGICAL_OR, "||", startLine, startColumn);
                }
                return new Token(TokenType.BITWISE_OR, "|", startLine, startColumn);
                
            case '~':
                pos++;
                column++;
                return new Token(TokenType.BITWISE_NOT, "~", startLine, startColumn);
                
            case '(':
                pos++;
                column++;
                return new Token(TokenType.LPAREN, "(", startLine, startColumn);
                
            case ')':
                pos++;
                column++;
                return new Token(TokenType.RPAREN, ")", startLine, startColumn);
                
            case '{':
                pos++;
                column++;
                return new Token(TokenType.LBRACE, "{", startLine, startColumn);
                
            case '}':
                pos++;
                column++;
                return new Token(TokenType.RBRACE, "}", startLine, startColumn);
                
            case '[':
                pos++;
                column++;
                return new Token(TokenType.LBRACKET, "[", startLine, startColumn);
                
            case ']':
                pos++;
                column++;
                return new Token(TokenType.RBRACKET, "]", startLine, startColumn);
                
            case ';':
                pos++;
                column++;
                return new Token(TokenType.SEMICOLON, ";", startLine, startColumn);
                
            case ',':
                pos++;
                column++;
                return new Token(TokenType.COMMA, ",", startLine, startColumn);
                
            case '.':
                pos++;
                column++;
                return new Token(TokenType.DOT, ".", startLine, startColumn);
                
            case ':':
                pos++;
                column++;
                if (pos < source.length() && source.charAt(pos) == ':') {
                    pos++;
                    column++;
                    return new Token(TokenType.DOUBLE_COLON, "::", startLine, startColumn);
                }
                return new Token(TokenType.COLON, ":", startLine, startColumn);
                
            case '?':
                pos++;
                column++;
                return new Token(TokenType.QUESTION, "?", startLine, startColumn);
                
            default:
                pos++;
                column++;
                return new Token(TokenType.EOF, String.valueOf(c), startLine, startColumn);
        }
    }
    
    private void advance() {
        currentToken = nextToken();
    }
    
    private void expect(TokenType expected) {
        if (currentToken.type != expected) {
            throw new RuntimeException(String.format("Expected %s, got %s at line %d, column %d",
                    expected, currentToken.type, currentToken.line, currentToken.column));
        }
        advance();
    }
    
    // Parser methods
    private AstNode parsePrimary() {
        switch (currentToken.type) {
            case NUMBER:
                AstNode numNode = new AstNode(AstType.NUMBER, currentToken.line, currentToken.column);
                numNode.value = Integer.parseInt(currentToken.value);
                advance();
                return numNode;
                
            case IDENTIFIER:
                AstNode idNode = new AstNode(AstType.IDENTIFIER, currentToken.line, currentToken.column);
                idNode.name = currentToken.value;
                advance();
                
                // Check for function calls
                if (currentToken.type == TokenType.LPAREN) {
                    AstNode callNode = new AstNode(AstType.FUNCTION_CALL, idNode.line, idNode.column);
                    callNode.funcName = idNode.name;
                    advance(); // consume '('
                    
                    if (currentToken.type != TokenType.RPAREN) {
                        callNode.funcArgs = parseExpression();
                        AstNode arg = callNode.funcArgs;
                        while (currentToken.type == TokenType.COMMA) {
                            advance(); // consume ','
                            arg.next = parseExpression();
                            arg = arg.next;
                        }
                    }
                    expect(TokenType.RPAREN);
                    return callNode;
                }
                
                return idNode;
                
            case LPAREN:
                advance(); // consume '('
                AstNode expr = parseExpression();
                expect(TokenType.RPAREN);
                return expr;
                
            default:
                throw new RuntimeException("Unexpected token in primary expression: " + currentToken);
        }
    }
    
    private AstNode parseExpression() {
        return parseLogicalOr();
    }
    
    private AstNode parseLogicalOr() {
        AstNode node = parseLogicalAnd();
        
        while (currentToken.type == TokenType.LOGICAL_OR) {
            AstNode opNode = new AstNode(AstType.OP, currentToken.line, currentToken.column);
            opNode.op = currentToken.type.ordinal();
            opNode.left = node;
            advance();
            opNode.right = parseLogicalAnd();
            node = opNode;
        }
        
        return node;
    }
    
    private AstNode parseLogicalAnd() {
        AstNode node = parseEquality();
        
        while (currentToken.type == TokenType.LOGICAL_AND) {
            AstNode opNode = new AstNode(AstType.OP, currentToken.line, currentToken.column);
            opNode.op = currentToken.type.ordinal();
            opNode.left = node;
            advance();
            opNode.right = parseEquality();
            node = opNode;
        }
        
        return node;
    }
    
    private AstNode parseEquality() {
        AstNode node = parseRelational();
        
        while (currentToken.type == TokenType.EQUALS || currentToken.type == TokenType.NOT_EQUALS) {
            AstNode opNode = new AstNode(AstType.OP, currentToken.line, currentToken.column);
            opNode.op = currentToken.type.ordinal();
            opNode.left = node;
            advance();
            opNode.right = parseRelational();
            node = opNode;
        }
        
        return node;
    }
    
    private AstNode parseRelational() {
        AstNode node = parseAdditive();
        
        while (currentToken.type == TokenType.GREATER || currentToken.type == TokenType.GREATER_EQUAL ||
               currentToken.type == TokenType.LESS || currentToken.type == TokenType.LESS_EQUAL) {
            AstNode opNode = new AstNode(AstType.OP, currentToken.line, currentToken.column);
            opNode.op = currentToken.type.ordinal();
            opNode.left = node;
            advance();
            opNode.right = parseAdditive();
            node = opNode;
        }
        
        return node;
    }
    
    private AstNode parseAdditive() {
        AstNode node = parseMultiplicative();
        
        while (currentToken.type == TokenType.PLUS || currentToken.type == TokenType.MINUS) {
            AstNode opNode = new AstNode(AstType.OP, currentToken.line, currentToken.column);
            opNode.op = currentToken.type.ordinal();
            opNode.left = node;
            advance();
            opNode.right = parseMultiplicative();
            node = opNode;
        }
        
        return node;
    }
    
    private AstNode parseMultiplicative() {
        AstNode node = parseUnary();
        
        while (currentToken.type == TokenType.STAR || currentToken.type == TokenType.DIVIDE || 
               currentToken.type == TokenType.MODULO) {
            AstNode opNode = new AstNode(AstType.OP, currentToken.line, currentToken.column);
            opNode.op = currentToken.type.ordinal();
            opNode.left = node;
            advance();
            opNode.right = parseUnary();
            node = opNode;
        }
        
        return node;
    }
    
    private AstNode parseUnary() {
        if (currentToken.type == TokenType.LOGICAL_NOT || currentToken.type == TokenType.MINUS) {
            AstNode node = new AstNode(AstType.OP, currentToken.line, currentToken.column);
            node.op = currentToken.type.ordinal();
            advance();
            node.right = parseUnary();
            return node;
        }
        
        return parsePrimary();
    }
    
    private AstNode parseStatement() {
        switch (currentToken.type) {
            case LET:
                advance(); // consume 'let'
                AstNode varNode = new AstNode(AstType.VAR_DECL, currentToken.line, currentToken.column);
                expect(TokenType.IDENTIFIER);
                varNode.varName = currentToken.value;
                advance();
                
                if (currentToken.type == TokenType.ASSIGN) {
                    advance(); // consume '='
                    varNode.initExpr = parseExpression();
                }
                expect(TokenType.SEMICOLON);
                return varNode;
                
            case IF:
                advance(); // consume 'if'
                AstNode ifNode = new AstNode(AstType.IF, currentToken.line, currentToken.column);
                expect(TokenType.LPAREN);
                ifNode.cond = parseExpression();
                expect(TokenType.RPAREN);
                ifNode.body = parseStatement();
                
                if (currentToken.type == TokenType.ELSE) {
                    advance(); // consume 'else'
                    ifNode.right = parseStatement();
                }
                return ifNode;
                
            case RET:
                advance(); // consume 'ret'
                AstNode retNode = new AstNode(AstType.RET, currentToken.line, currentToken.column);
                if (currentToken.type != TokenType.SEMICOLON) {
                    retNode.left = parseExpression();
                }
                expect(TokenType.SEMICOLON);
                return retNode;
                
            case LBRACE:
                return parseBlock();
                
            default:
                // Try to parse as expression statement
                AstNode expr = parseExpression();
                if (currentToken.type == TokenType.SEMICOLON) {
                    advance();
                }
                return expr;
        }
    }
    
    private AstNode parseBlock() {
        AstNode blockNode = new AstNode(AstType.BLOCK, currentToken.line, currentToken.column);
        expect(TokenType.LBRACE);
        
        AstNode stmt = null;
        AstNode lastStmt = null;
        
        while (currentToken.type != TokenType.RBRACE && currentToken.type != TokenType.EOF) {
            stmt = parseStatement();
            if (lastStmt == null) {
                blockNode.body = stmt;
            } else {
                lastStmt.next = stmt;
            }
            lastStmt = stmt;
        }
        
        expect(TokenType.RBRACE);
        return blockNode;
    }
    
    private AstNode parseFunctionDefinition() {
        AstNode funcNode = new AstNode(AstType.FUNCTION_DEFINITION, currentToken.line, currentToken.column);
        
        if (currentToken.type == TokenType.DEF) {
            advance(); // consume 'def'
        }
        
        expect(TokenType.FUNC);
        expect(TokenType.IDENTIFIER);
        funcNode.funcName = currentToken.value;
        advance();
        
        expect(TokenType.LPAREN);
        
        // Parse parameters
        if (currentToken.type != TokenType.RPAREN) {
            AstNode param = new AstNode(AstType.PARAMETER, currentToken.line, currentToken.column);
            expect(TokenType.IDENTIFIER);
            param.name = currentToken.value;
            advance();
            
            funcNode.funcParams = param;
            AstNode lastParam = param;
            
            while (currentToken.type == TokenType.COMMA) {
                advance(); // consume ','
                param = new AstNode(AstType.PARAMETER, currentToken.line, currentToken.column);
                expect(TokenType.IDENTIFIER);
                param.name = currentToken.value;
                advance();
                
                lastParam.next = param;
                lastParam = param;
            }
        }
        
        expect(TokenType.RPAREN);
        
        // Parse return type
        if (currentToken.type == TokenType.ARROW) {
            advance(); // consume '->'
            // Skip type for now
            advance();
        }
        
        // Parse function body
        funcNode.funcBody = parseBlock();
        
        return funcNode;
    }
    
    private AstNode parseTopLevelDeclaration() {
        switch (currentToken.type) {
            case DEF:
            case FUNC:
                return parseFunctionDefinition();
            default:
                return parseStatement();
        }
    }
    
    private AstNode parseProgram() {
        AstNode programNode = new AstNode(AstType.PROGRAM, 1, 1);
        AstNode decl = null;
        AstNode lastDecl = null;
        
        while (currentToken.type != TokenType.EOF) {
            decl = parseTopLevelDeclaration();
            if (programNode.body == null) {
                programNode.body = decl;
            } else {
                lastDecl.next = decl;
            }
            lastDecl = decl;
        }
        
        return programNode;
    }
    
    // Semantic analysis
    private void semanticPass(AstNode node) {
        if (node == null) return;
        
        switch (node.type) {
            case VAR_DECL:
                // Add to symbol table
                Symbol sym = new Symbol(node.varName, "int");
                currentScope.symbols.put(node.varName, sym);
                
                if (node.initExpr != null) {
                    semanticPass(node.initExpr);
                }
                break;
                
            case FUNCTION_DEFINITION:
                // Add function to symbol table
                Symbol funcSym = new Symbol(node.funcName, "function");
                funcSym.isFunction = true;
                currentScope.symbols.put(node.funcName, funcSym);
                
                // Push new scope for function parameters and body
                Scope oldScope = currentScope;
                currentScope = new Scope(currentScope);
                
                // Add parameters to symbol table
                AstNode param = node.funcParams;
                while (param != null) {
                    Symbol paramSym = new Symbol(param.name, "int");
                    paramSym.isParameter = true;
                    currentScope.symbols.put(param.name, paramSym);
                    param = param.next;
                }
                
                semanticPass(node.funcBody);
                
                // Restore scope
                currentScope = oldScope;
                break;
                
            case IDENTIFIER:
                // Check if variable exists
                if (!symbolExists(node.name)) {
                    throw new RuntimeException("Undefined variable: " + node.name + " at line " + node.line);
                }
                break;
                
            case FUNCTION_CALL:
                // Check if function exists
                if (!symbolExists(node.funcName)) {
                    throw new RuntimeException("Undefined function: " + node.funcName + " at line " + node.line);
                }
                
                // Check arguments
                AstNode arg = node.funcArgs;
                while (arg != null) {
                    semanticPass(arg);
                    arg = arg.next;
                }
                break;
                
            case OP:
                semanticPass(node.left);
                semanticPass(node.right);
                break;
                
            case IF:
            case WHILE_LOOP:
                semanticPass(node.cond);
                semanticPass(node.body);
                break;
                
            case RET:
                if (node.left != null) {
                    semanticPass(node.left);
                }
                break;
                
            case BLOCK:
                AstNode stmt = node.body;
                while (stmt != null) {
                    semanticPass(stmt);
                    stmt = stmt.next;
                }
                break;
        }
        
        // Recursively process child nodes
        semanticPass(node.left);
        semanticPass(node.right);
        semanticPass(node.next);
    }
    
    private boolean symbolExists(String name) {
        Scope scope = currentScope;
        while (scope != null) {
            if (scope.symbols.containsKey(name)) {
                return true;
            }
            scope = scope.parent;
        }
        return false;
    }
    
    // Code generation
    private void generateCode(AstNode node, StringBuilder output) {
        if (node == null) return;
        
        switch (node.type) {
            case NUMBER:
                output.append("    mov rax, ").append(node.value).append("\n");
                output.append("    push rax\n");
                break;
                
            case IDENTIFIER:
                output.append("    mov rax, [rbp-8]\n"); // Simplified
                output.append("    push rax\n");
                break;
                
            case OP:
                generateCode(node.left, output);
                generateCode(node.right, output);
                output.append("    pop rbx\n");
                output.append("    pop rax\n");
                
                switch (TokenType.values()[node.op]) {
                    case PLUS:
                        output.append("    add rax, rbx\n");
                        break;
                    case MINUS:
                        output.append("    sub rax, rbx\n");
                        break;
                    case STAR:
                        output.append("    imul rax, rbx\n");
                        break;
                    case DIVIDE:
                        output.append("    xor rdx, rdx\n");
                        output.append("    idiv rbx\n");
                        break;
                }
                output.append("    push rax\n");
                break;
                
            case VAR_DECL:
                if (node.initExpr != null) {
                    generateCode(node.initExpr, output);
                    output.append("    pop rax\n");
                    output.append("    mov [rbp-8], rax\n"); // Simplified
                }
                break;
                
            case RET:
                if (node.left != null) {
                    generateCode(node.left, output);
                    output.append("    pop rax\n");
                } else {
                    output.append("    mov rax, 0\n");
                }
                output.append("    leave\n");
                output.append("    ret\n");
                break;
                
            case FUNCTION_CALL:
                if ("print".equals(node.funcName)) {
                    generateCode(node.funcArgs, output);
                    output.append("    pop rdi\n");
                    output.append("    call print_int\n");
                }
                break;
                
            case BLOCK:
                AstNode stmt = node.body;
                while (stmt != null) {
                    generateCode(stmt, output);
                    stmt = stmt.next;
                }
                break;
        }
    }
    
    // Main compilation method
    public String compile() {
        try {
            // Initialize
            advance(); // Load first token
            
            // Parse
            System.out.println("Parsing...");
            AstNode ast = parseProgram();
            System.out.println("Parsing completed successfully!");
            
            // Semantic analysis
            System.out.println("Performing semantic analysis...");
            semanticPass(ast);
            System.out.println("Semantic analysis completed successfully!");
            
            // Generate code
            System.out.println("Generating assembly code...");
            StringBuilder output = new StringBuilder();
            
            // Assembly header
            output.append("section .text\n");
            output.append("global main\n");
            output.append("extern printf\n");
            output.append("main:\n");
            output.append("    push rbp\n");
            output.append("    mov rbp, rsp\n");
            output.append("    sub rsp, 1024\n");
            
            // Generate code for main function
            generateCode(ast, output);
            
            // Add print function
            output.append("print_int:\n");
            output.append("    push rbp\n");
            output.append("    mov rbp, rsp\n");
            output.append("    mov rsi, rdi\n");
            output.append("    mov rdi, print_fmt\n");
            output.append("    mov rax, 0\n");
            output.append("    call printf\n");
            output.append("    leave\n");
            output.append("    ret\n");
            
            output.append("section .data\n");
            output.append("print_fmt: db \"%d\", 10, 0\n");
            
            System.out.println("Assembly code generated successfully!");
            return output.toString();
            
        } catch (Exception e) {
            System.err.println("Compilation error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    // Main method for testing
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java EonCompilerEnhanced <source_file>");
            System.exit(1);
        }
        
        try {
            // Read source file
            String source = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(args[0])));
            
            System.out.println("Enhanced EON Compiler v2.0 (Java)");
            System.out.println("Source file: " + args[0]);
            System.out.println("File size: " + source.length() + " bytes");
            System.out.println();
            
            // Compile
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String assembly = compiler.compile();
            
            if (assembly != null) {
                // Write assembly to file
                java.nio.file.Files.write(java.nio.file.Paths.get("out.asm"), assembly.getBytes());
                System.out.println("Assembly code written to out.asm");
                System.out.println();
                System.out.println("Compilation successful!");
                System.out.println("To compile and run:");
                System.out.println("  nasm -f elf64 out.asm");
                System.out.println("  gcc out.o -o program");
                System.out.println("  ./program");
            } else {
                System.err.println("Compilation failed!");
                System.exit(1);
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
