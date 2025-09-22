' eon_vb_parser.vb
' Visual Basic parser for Eon AST data structures
' Implements parser for Eon language using Visual Basic

Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Text

' === Token Types ===
Public Enum TokenType
    EOF_TOKEN
    IDENTIFIER
    NUMBER
    STRING
    DEF
    MODEL
    FUNC
    LOOP
    IF
    ELSE
    LET
    RET
    LBRACE
    RBRACE
    LPAREN
    RPAREN
    SEMICOLON
    ASSIGN
    PLUS
    MINUS
    MULTIPLY
    DIVIDE
    EQUALS
    NOT_EQUALS
    GREATER
    LESS
    GREATER_EQUAL
    LESS_EQUAL
End Enum

' === Token Structure ===
Public Class Token
    Public Property Type As TokenType
    Public Property Value As String
    Public Property Line As Integer
    Public Property Column As Integer
    
    Public Sub New(Optional tokenType As TokenType = TokenType.EOF_TOKEN, 
                   Optional value As String = "", 
                   Optional line As Integer = 0, 
                   Optional column As Integer = 0)
        Me.Type = tokenType
        Me.Value = value
        Me.Line = line
        Me.Column = column
    End Sub
End Class

' === AST Node Types ===
Public Enum ASTNodeType
    PROGRAM
    FUNCTION_DEF
    MODEL_DEF
    VARIABLE_DECL
    ASSIGNMENT
    IF_STMT
    LOOP_STMT
    RETURN_STMT
    BLOCK
    BINARY_OP
    UNARY_OP
    IDENTIFIER
    LITERAL
    FUNCTION_CALL
End Enum

' === AST Node Structure ===
Public Class ASTNode
    Public Property Type As ASTNodeType
    Public Property Value As String
    Public Property Children As List(Of ASTNode)
    Public Property Line As Integer
    Public Property Column As Integer
    
    Public Sub New(Optional nodeType As ASTNodeType = ASTNodeType.PROGRAM, 
                   Optional value As String = "", 
                   Optional line As Integer = 0, 
                   Optional column As Integer = 0)
        Me.Type = nodeType
        Me.Value = value
        Me.Line = line
        Me.Column = column
        Me.Children = New List(Of ASTNode)()
    End Sub
    
    Public Sub AddChild(child As ASTNode)
        Children.Add(child)
    End Sub
End Class

' === Lexer Class ===
Public Class Lexer
    Private source As String
    Private position As Integer
    Private line As Integer
    Private column As Integer
    Private currentChar As Char
    
    Private keywords As Dictionary(Of String, TokenType)
    
    Public Sub New(source As String)
        Me.source = source
        Me.position = 0
        Me.line = 1
        Me.column = 1
        
        ' Initialize keywords
        keywords = New Dictionary(Of String, TokenType)()
        keywords.Add("def", TokenType.DEF)
        keywords.Add("model", TokenType.MODEL)
        keywords.Add("func", TokenType.FUNC)
        keywords.Add("loop", TokenType.LOOP)
        keywords.Add("if", TokenType.IF)
        keywords.Add("else", TokenType.ELSE)
        keywords.Add("let", TokenType.LET)
        keywords.Add("ret", TokenType.RET)
        
        If source.Length > 0 Then
            currentChar = source(0)
        Else
            currentChar = Chr(0)
        End If
    End Sub
    
    Private Sub Advance()
        If position < source.Length Then
            currentChar = source(position)
            position += 1
            column += 1
            If currentChar = vbLf Then
                line += 1
                column = 1
            End If
        Else
            currentChar = Chr(0)
        End If
    End Sub
    
    Private Sub SkipWhitespace()
        While currentChar = " "c OrElse currentChar = vbTab OrElse currentChar = vbCr
            Advance()
        End While
    End Sub
    
    Private Function IsLetter(c As Char) As Boolean
        Return Char.IsLetter(c) OrElse c = "_"c
    End Function
    
    Private Function IsDigit(c As Char) As Boolean
        Return Char.IsDigit(c)
    End Function
    
    Private Function IsAlphanumeric(c As Char) As Boolean
        Return IsLetter(c) OrElse IsDigit(c)
    End Function
    
    Private Function ReadIdentifier() As String
        Dim result As New StringBuilder()
        While IsAlphanumeric(currentChar)
            result.Append(currentChar)
            Advance()
        End While
        Return result.ToString()
    End Function
    
    Private Function ReadNumber() As String
        Dim result As New StringBuilder()
        While IsDigit(currentChar)
            result.Append(currentChar)
            Advance()
        End While
        Return result.ToString()
    End Function
    
    Private Function ReadString() As String
        Dim result As New StringBuilder()
        Advance() ' skip opening quote
        While currentChar <> """"c AndAlso currentChar <> Chr(0)
            If currentChar = "\"c Then
                Advance()
                Select Case currentChar
                    Case "n"c
                        result.Append(vbLf)
                    Case "t"c
                        result.Append(vbTab)
                    Case "r"c
                        result.Append(vbCr)
                    Case "\"c
                        result.Append("\"c)
                    Case """"c
                        result.Append(""""c)
                    Case Else
                        result.Append(currentChar)
                End Select
            Else
                result.Append(currentChar)
            End If
            Advance()
        End While
        If currentChar = """"c Then
            Advance() ' skip closing quote
        End If
        Return result.ToString()
    End Function
    
    Public Function NextToken() As Token
        While currentChar <> Chr(0)
            SkipWhitespace()
            
            If currentChar = Chr(0) Then Exit While
            
            Dim startLine As Integer = line
            Dim startColumn As Integer = column
            
            If IsLetter(currentChar) Then
                Dim identifier As String = ReadIdentifier()
                If keywords.ContainsKey(identifier) Then
                    Return New Token(keywords(identifier), identifier, startLine, startColumn)
                End If
                Return New Token(TokenType.IDENTIFIER, identifier, startLine, startColumn)
            End If
            
            If IsDigit(currentChar) Then
                Dim number As String = ReadNumber()
                Return New Token(TokenType.NUMBER, number, startLine, startColumn)
            End If
            
            If currentChar = """"c Then
                Dim str As String = ReadString()
                Return New Token(TokenType.STRING, str, startLine, startColumn)
            End If
            
            Select Case currentChar
                Case "{"c
                    Advance()
                    Return New Token(TokenType.LBRACE, "{", startLine, startColumn)
                Case "}"c
                    Advance()
                    Return New Token(TokenType.RBRACE, "}", startLine, startColumn)
                Case "("c
                    Advance()
                    Return New Token(TokenType.LPAREN, "(", startLine, startColumn)
                Case ")"c
                    Advance()
                    Return New Token(TokenType.RPAREN, ")", startLine, startColumn)
                Case ";"c
                    Advance()
                    Return New Token(TokenType.SEMICOLON, ";", startLine, startColumn)
                Case "="c
                    Advance()
                    If currentChar = "="c Then
                        Advance()
                        Return New Token(TokenType.EQUALS, "==", startLine, startColumn)
                    End If
                    Return New Token(TokenType.ASSIGN, "=", startLine, startColumn)
                Case "+"c
                    Advance()
                    Return New Token(TokenType.PLUS, "+", startLine, startColumn)
                Case "-"c
                    Advance()
                    Return New Token(TokenType.MINUS, "-", startLine, startColumn)
                Case "*"c
                    Advance()
                    Return New Token(TokenType.MULTIPLY, "*", startLine, startColumn)
                Case "/"c
                    Advance()
                    Return New Token(TokenType.DIVIDE, "/", startLine, startColumn)
                Case ">"c
                    Advance()
                    If currentChar = "="c Then
                        Advance()
                        Return New Token(TokenType.GREATER_EQUAL, ">=", startLine, startColumn)
                    End If
                    Return New Token(TokenType.GREATER, ">", startLine, startColumn)
                Case "<"c
                    Advance()
                    If currentChar = "="c Then
                        Advance()
                        Return New Token(TokenType.LESS_EQUAL, "<=", startLine, startColumn)
                    End If
                    Return New Token(TokenType.LESS, "<", startLine, startColumn)
                Case "!"c
                    Advance()
                    If currentChar = "="c Then
                        Advance()
                        Return New Token(TokenType.NOT_EQUALS, "!=", startLine, startColumn)
                    End If
                    Exit Select
                Case Else
                    Advance()
                    Exit Select
            End Select
        End While
        
        Return New Token(TokenType.EOF_TOKEN, "", line, column)
    End Function
End Class

' === Parser Class ===
Public Class Parser
    Private lexer As Lexer
    Private currentToken As Token
    
    Public Sub New(source As String)
        lexer = New Lexer(source)
        Advance()
    End Sub
    
    Private Sub Advance()
        currentToken = lexer.NextToken()
    End Sub
    
    Private Sub Expect(expected As TokenType)
        If currentToken.Type <> expected Then
            Console.WriteLine("Error: Expected " & expected.ToString() & " but got " & currentToken.Type.ToString())
        End If
        Advance()
    End Sub
    
    Private Function Match(expected As TokenType) As Boolean
        If currentToken.Type = expected Then
            Advance()
            Return True
        End If
        Return False
    End Function
    
    Public Function ParseProgram() As ASTNode
        Dim program As New ASTNode(ASTNodeType.PROGRAM)
        
        While currentToken.Type <> TokenType.EOF_TOKEN
            Dim declaration As ASTNode = ParseDeclaration()
            If declaration IsNot Nothing Then
                program.AddChild(declaration)
            End If
        End While
        
        Return program
    End Function
    
    Private Function ParseDeclaration() As ASTNode
        Select Case currentToken.Type
            Case TokenType.DEF
                Return ParseFunctionDefinition()
            Case TokenType.MODEL
                Return ParseModelDefinition()
            Case Else
                Return ParseStatement()
        End Select
    End Function
    
    Private Function ParseFunctionDefinition() As ASTNode
        Expect(TokenType.DEF)
        Expect(TokenType.FUNC)
        
        Dim func As New ASTNode(ASTNodeType.FUNCTION_DEF, currentToken.Value)
        Expect(TokenType.IDENTIFIER)
        
        Expect(TokenType.LPAREN)
        ' Parse parameters (simplified)
        While currentToken.Type <> TokenType.RPAREN
            Advance()
        End While
        Expect(TokenType.RPAREN)
        
        Dim body As ASTNode = ParseBlock()
        func.AddChild(body)
        
        Return func
    End Function
    
    Private Function ParseModelDefinition() As ASTNode
        Expect(TokenType.MODEL)
        
        Dim model As New ASTNode(ASTNodeType.MODEL_DEF, currentToken.Value)
        Expect(TokenType.IDENTIFIER)
        
        Expect(TokenType.LBRACE)
        ' Parse fields (simplified)
        While currentToken.Type <> TokenType.RBRACE
            Advance()
        End While
        Expect(TokenType.RBRACE)
        
        Return model
    End Function
    
    Private Function ParseStatement() As ASTNode
        Select Case currentToken.Type
            Case TokenType.LET
                Return ParseVariableDeclaration()
            Case TokenType.IF
                Return ParseIfStatement()
            Case TokenType.LOOP
                Return ParseLoopStatement()
            Case TokenType.RET
                Return ParseReturnStatement()
            Case TokenType.LBRACE
                Return ParseBlock()
            Case Else
                Return ParseExpression()
        End Select
    End Function
    
    Private Function ParseVariableDeclaration() As ASTNode
        Expect(TokenType.LET)
        
        Dim var As New ASTNode(ASTNodeType.VARIABLE_DECL, currentToken.Value)
        Expect(TokenType.IDENTIFIER)
        
        If Match(TokenType.ASSIGN) Then
            Dim expr As ASTNode = ParseExpression()
            var.AddChild(expr)
        End If
        
        Return var
    End Function
    
    Private Function ParseIfStatement() As ASTNode
        Expect(TokenType.IF)
        
        Dim ifStmt As New ASTNode(ASTNodeType.IF_STMT)
        
        Expect(TokenType.LPAREN)
        Dim condition As ASTNode = ParseExpression()
        ifStmt.AddChild(condition)
        Expect(TokenType.RPAREN)
        
        Dim thenBlock As ASTNode = ParseStatement()
        ifStmt.AddChild(thenBlock)
        
        If Match(TokenType.ELSE) Then
            Dim elseBlock As ASTNode = ParseStatement()
            ifStmt.AddChild(elseBlock)
        End If
        
        Return ifStmt
    End Function
    
    Private Function ParseLoopStatement() As ASTNode
        Expect(TokenType.LOOP)
        
        Dim loop As New ASTNode(ASTNodeType.LOOP_STMT)
        Dim body As ASTNode = ParseStatement()
        loop.AddChild(body)
        
        Return loop
    End Function
    
    Private Function ParseReturnStatement() As ASTNode
        Expect(TokenType.RET)
        
        Dim ret As New ASTNode(ASTNodeType.RETURN_STMT)
        If currentToken.Type <> TokenType.SEMICOLON Then
            Dim expr As ASTNode = ParseExpression()
            ret.AddChild(expr)
        End If
        
        Return ret
    End Function
    
    Private Function ParseBlock() As ASTNode
        Expect(TokenType.LBRACE)
        
        Dim block As New ASTNode(ASTNodeType.BLOCK)
        
        While currentToken.Type <> TokenType.RBRACE
            Dim stmt As ASTNode = ParseStatement()
            block.AddChild(stmt)
        End While
        
        Expect(TokenType.RBRACE)
        Return block
    End Function
    
    Private Function ParseExpression() As ASTNode
        Return ParseEquality()
    End Function
    
    Private Function ParseEquality() As ASTNode
        Dim left As ASTNode = ParseRelational()
        
        While currentToken.Type = TokenType.EQUALS OrElse currentToken.Type = TokenType.NOT_EQUALS
            Dim op As TokenType = currentToken.Type
            Advance()
            Dim right As ASTNode = ParseRelational()
            
            Dim binaryOp As New ASTNode(ASTNodeType.BINARY_OP, If(op = TokenType.EQUALS, "==", "!="))
            binaryOp.AddChild(left)
            binaryOp.AddChild(right)
            left = binaryOp
        End While
        
        Return left
    End Function
    
    Private Function ParseRelational() As ASTNode
        Dim left As ASTNode = ParseAdditive()
        
        While currentToken.Type = TokenType.GREATER OrElse 
              currentToken.Type = TokenType.GREATER_EQUAL OrElse
              currentToken.Type = TokenType.LESS OrElse
              currentToken.Type = TokenType.LESS_EQUAL
            Dim op As TokenType = currentToken.Type
            Advance()
            Dim right As ASTNode = ParseAdditive()
            
            Dim opStr As String = ""
            Select Case op
                Case TokenType.GREATER
                    opStr = ">"
                Case TokenType.GREATER_EQUAL
                    opStr = ">="
                Case TokenType.LESS
                    opStr = "<"
                Case TokenType.LESS_EQUAL
                    opStr = "<="
            End Select
            
            Dim binaryOp As New ASTNode(ASTNodeType.BINARY_OP, opStr)
            binaryOp.AddChild(left)
            binaryOp.AddChild(right)
            left = binaryOp
        End While
        
        Return left
    End Function
    
    Private Function ParseAdditive() As ASTNode
        Dim left As ASTNode = ParseMultiplicative()
        
        While currentToken.Type = TokenType.PLUS OrElse currentToken.Type = TokenType.MINUS
            Dim op As TokenType = currentToken.Type
            Advance()
            Dim right As ASTNode = ParseMultiplicative()
            
            Dim binaryOp As New ASTNode(ASTNodeType.BINARY_OP, If(op = TokenType.PLUS, "+", "-"))
            binaryOp.AddChild(left)
            binaryOp.AddChild(right)
            left = binaryOp
        End While
        
        Return left
    End Function
    
    Private Function ParseMultiplicative() As ASTNode
        Dim left As ASTNode = ParseUnary()
        
        While currentToken.Type = TokenType.MULTIPLY OrElse currentToken.Type = TokenType.DIVIDE
            Dim op As TokenType = currentToken.Type
            Advance()
            Dim right As ASTNode = ParseUnary()
            
            Dim binaryOp As New ASTNode(ASTNodeType.BINARY_OP, If(op = TokenType.MULTIPLY, "*", "/"))
            binaryOp.AddChild(left)
            binaryOp.AddChild(right)
            left = binaryOp
        End While
        
        Return left
    End Function
    
    Private Function ParseUnary() As ASTNode
        If currentToken.Type = TokenType.MINUS Then
            Advance()
            Dim operand As ASTNode = ParsePrimary()
            Dim unary As New ASTNode(ASTNodeType.UNARY_OP, "-")
            unary.AddChild(operand)
            Return unary
        End If
        
        Return ParsePrimary()
    End Function
    
    Private Function ParsePrimary() As ASTNode
        Select Case currentToken.Type
            Case TokenType.NUMBER
                Dim literal As New ASTNode(ASTNodeType.LITERAL, currentToken.Value)
                Advance()
                Return literal
            Case TokenType.STRING
                Dim literal As New ASTNode(ASTNodeType.LITERAL, currentToken.Value)
                Advance()
                Return literal
            Case TokenType.IDENTIFIER
                Dim identifier As New ASTNode(ASTNodeType.IDENTIFIER, currentToken.Value)
                Advance()
                Return identifier
            Case TokenType.LPAREN
                Advance()
                Dim expr As ASTNode = ParseExpression()
                Expect(TokenType.RPAREN)
                Return expr
            Case Else
                Console.WriteLine("Error: Unexpected token in primary expression")
                Return Nothing
        End Select
    End Function
End Class

' === Code Generator Class ===
Public Class CodeGenerator
    Private output As StringBuilder
    Private labelCount As Integer
    Private tempCount As Integer
    
    Public Sub New()
        output = New StringBuilder()
        labelCount = 0
        tempCount = 0
    End Sub
    
    Private Function NewLabel() As String
        labelCount += 1
        Return "label_" & labelCount.ToString()
    End Function
    
    Private Function NewTemp() As String
        tempCount += 1
        Return "temp_" & tempCount.ToString()
    End Function
    
    Public Sub GenerateProgram(node As ASTNode)
        output.AppendLine("section .text")
        output.AppendLine("global _start")
        output.AppendLine("_start:")
        output.AppendLine("    call main")
        output.AppendLine("    mov rax, 60")
        output.AppendLine("    mov rdi, 0")
        output.AppendLine("    syscall")
        output.AppendLine()
        
        For Each child In node.Children
            GenerateDeclaration(child)
        Next
    End Sub
    
    Private Sub GenerateDeclaration(node As ASTNode)
        Select Case node.Type
            Case ASTNodeType.FUNCTION_DEF
                GenerateFunction(node)
            Case ASTNodeType.MODEL_DEF
                GenerateModel(node)
            Case Else
                GenerateStatement(node)
        End Select
    End Sub
    
    Private Sub GenerateFunction(node As ASTNode)
        output.AppendLine("main:")
        output.AppendLine("    push rbp")
        output.AppendLine("    mov rbp, rsp")
        output.AppendLine("    sub rsp, 1024") ' Allocate stack space
        
        If node.Children.Count > 0 Then
            GenerateStatement(node.Children(0))
        End If
        
        output.AppendLine("    mov rax, 0")
        output.AppendLine("    leave")
        output.AppendLine("    ret")
        output.AppendLine()
    End Sub
    
    Private Sub GenerateModel(node As ASTNode)
        output.AppendLine("; Model: " & node.Value)
    End Sub
    
    Private Sub GenerateStatement(node As ASTNode)
        Select Case node.Type
            Case ASTNodeType.VARIABLE_DECL
                GenerateVariableDeclaration(node)
            Case ASTNodeType.ASSIGNMENT
                GenerateAssignment(node)
            Case ASTNodeType.IF_STMT
                GenerateIfStatement(node)
            Case ASTNodeType.LOOP_STMT
                GenerateLoopStatement(node)
            Case ASTNodeType.RETURN_STMT
                GenerateReturnStatement(node)
            Case ASTNodeType.BLOCK
                GenerateBlock(node)
            Case Else
                GenerateExpression(node)
        End Select
    End Sub
    
    Private Sub GenerateVariableDeclaration(node As ASTNode)
        output.AppendLine("; Variable: " & node.Value)
        If node.Children.Count > 0 Then
            GenerateExpression(node.Children(0))
        End If
    End Sub
    
    Private Sub GenerateAssignment(node As ASTNode)
        If node.Children.Count > 0 Then
            GenerateExpression(node.Children(0))
        End If
    End Sub
    
    Private Sub GenerateIfStatement(node As ASTNode)
        If node.Children.Count >= 2 Then
            Dim elseLabel As String = NewLabel()
            Dim endLabel As String = NewLabel()
            
            GenerateExpression(node.Children(0))
            output.AppendLine("    cmp rax, 0")
            output.AppendLine("    je " & elseLabel)
            
            GenerateStatement(node.Children(1))
            output.AppendLine("    jmp " & endLabel)
            
            output.AppendLine(elseLabel & ":")
            If node.Children.Count > 2 Then
                GenerateStatement(node.Children(2))
            End If
            
            output.AppendLine(endLabel & ":")
        End If
    End Sub
    
    Private Sub GenerateLoopStatement(node As ASTNode)
        If node.Children.Count > 0 Then
            Dim loopLabel As String = NewLabel()
            Dim endLabel As String = NewLabel()
            
            output.AppendLine(loopLabel & ":")
            GenerateStatement(node.Children(0))
            output.AppendLine("    jmp " & loopLabel)
            output.AppendLine(endLabel & ":")
        End If
    End Sub
    
    Private Sub GenerateReturnStatement(node As ASTNode)
        If node.Children.Count > 0 Then
            GenerateExpression(node.Children(0))
        End If
        output.AppendLine("    mov rax, 0")
    End Sub
    
    Private Sub GenerateBlock(node As ASTNode)
        For Each child In node.Children
            GenerateStatement(child)
        Next
    End Sub
    
    Private Sub GenerateExpression(node As ASTNode)
        Select Case node.Type
            Case ASTNodeType.BINARY_OP
                GenerateBinaryOperation(node)
            Case ASTNodeType.UNARY_OP
                GenerateUnaryOperation(node)
            Case ASTNodeType.IDENTIFIER
                GenerateIdentifier(node)
            Case ASTNodeType.LITERAL
                GenerateLiteral(node)
        End Select
    End Sub
    
    Private Sub GenerateBinaryOperation(node As ASTNode)
        If node.Children.Count >= 2 Then
            GenerateExpression(node.Children(0))
            output.AppendLine("    push rax")
            GenerateExpression(node.Children(1))
            output.AppendLine("    pop rbx")
            
            Select Case node.Value
                Case "+"
                    output.AppendLine("    add rax, rbx")
                Case "-"
                    output.AppendLine("    sub rax, rbx")
                Case "*"
                    output.AppendLine("    mul rbx")
                Case "/"
                    output.AppendLine("    div rbx")
                Case "=="
                    output.AppendLine("    cmp rax, rbx")
                    output.AppendLine("    sete al")
                    output.AppendLine("    movzx rax, al")
                Case "!="
                    output.AppendLine("    cmp rax, rbx")
                    output.AppendLine("    setne al")
                    output.AppendLine("    movzx rax, al")
            End Select
        End If
    End Sub
    
    Private Sub GenerateUnaryOperation(node As ASTNode)
        If node.Children.Count > 0 Then
            GenerateExpression(node.Children(0))
            If node.Value = "-" Then
                output.AppendLine("    neg rax")
            End If
        End If
    End Sub
    
    Private Sub GenerateIdentifier(node As ASTNode)
        output.AppendLine("; Identifier: " & node.Value)
        output.AppendLine("    mov rax, 0") ' Placeholder
    End Sub
    
    Private Sub GenerateLiteral(node As ASTNode)
        If Char.IsDigit(node.Value(0)) Then
            output.AppendLine("    mov rax, " & node.Value)
        Else
            output.AppendLine("; String literal: " & node.Value)
            output.AppendLine("    mov rax, 0") ' Placeholder
        End If
    End Sub
    
    Public Function GetOutput() As String
        Return output.ToString()
    End Function
End Class

' === Bootstrap Compiler Class ===
Public Class BootstrapCompiler
    Public Shared Function Compile(source As String) As String
        Try
            Dim parser As New Parser(source)
            Dim ast As ASTNode = parser.ParseProgram()
            
            Dim generator As New CodeGenerator()
            generator.GenerateProgram(ast)
            
            Return generator.GetOutput()
        Catch ex As Exception
            Return "; Error: " & ex.Message & vbLf
        End Try
    End Function
    
    Public Shared Sub CompileFile(inputFile As String, outputFile As String)
        Try
            Dim source As String = File.ReadAllText(inputFile)
            Dim assembly As String = Compile(source)
            File.WriteAllText(outputFile, assembly)
            Console.WriteLine("Compilation successful. Output written to " & outputFile)
        Catch ex As Exception
            Console.WriteLine("Error: " & ex.Message)
        End Try
    End Sub
End Class

' === Main Module ===
Module Main
    Sub Main(args As String())
        If args.Length < 1 Then
            Console.WriteLine("Usage: eon_vb_parser <input_file> [output_file]")
            Console.WriteLine("Example: eon_vb_parser program.eon program.asm")
            Return
        End If
        
        Dim inputFile As String = args(0)
        Dim outputFile As String = If(args.Length > 1, args(1), "output.asm")
        
        BootstrapCompiler.CompileFile(inputFile, outputFile)
    End Sub
End Module
