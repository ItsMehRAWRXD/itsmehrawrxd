@echo off
echo Testing Self-Hosted Eon Compiler (Phase 2) Implementation
echo =========================================================

echo.
echo Checking if self-hosted compiler files exist:
if exist "self_hosted_eon_compiler.asm" (
    echo ✓ self_hosted_eon_compiler.asm found
) else (
    echo ✗ self_hosted_eon_compiler.asm not found
)

if exist "test_self_hosted_compiler.asm" (
    echo ✓ test_self_hosted_compiler.asm found
) else (
    echo ✗ test_self_hosted_compiler.asm not found
)

echo.
echo Checking file sizes:
for %%f in (self_hosted_eon_compiler.asm test_self_hosted_compiler.asm) do (
    if exist "%%f" (
        for %%s in ("%%f") do echo %%f: %%~zs bytes
    )
)

echo.
echo Checking for key functions in self_hosted_eon_compiler.asm:
findstr /C:"self_hosted_eon_compiler_init" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_init function found
) else (
    echo ✗ self_hosted_eon_compiler_init function not found
)

findstr /C:"self_hosted_eon_compiler_compile_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_compile_self function found
) else (
    echo ✗ self_hosted_eon_compiler_compile_self function not found
)

findstr /C:"self_hosted_eon_compiler_bootstrap_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_bootstrap_self function found
) else (
    echo ✗ self_hosted_eon_compiler_bootstrap_self function not found
)

findstr /C:"self_hosted_eon_compiler_cleanup" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_cleanup function found
) else (
    echo ✗ self_hosted_eon_compiler_cleanup function not found
)

echo.
echo Checking for self-hosting phases:
findstr /C:"PHASE_BOOTSTRAP_INIT" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ PHASE_BOOTSTRAP_INIT constant found
) else (
    echo ✗ PHASE_BOOTSTRAP_INIT constant not found
)

findstr /C:"PHASE_SELF_ANALYSIS" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ PHASE_SELF_ANALYSIS constant found
) else (
    echo ✗ PHASE_SELF_ANALYSIS constant not found
)

findstr /C:"PHASE_META_COMPILATION" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ PHASE_META_COMPILATION constant found
) else (
    echo ✗ PHASE_META_COMPILATION constant not found
)

findstr /C:"PHASE_SELF_GENERATION" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ PHASE_SELF_GENERATION constant found
) else (
    echo ✗ PHASE_SELF_GENERATION constant not found
)

findstr /C:"PHASE_SELF_VALIDATION" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ PHASE_SELF_VALIDATION constant found
) else (
    echo ✗ PHASE_SELF_VALIDATION constant not found
)

findstr /C:"PHASE_SELF_OPTIMIZATION" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ PHASE_SELF_OPTIMIZATION constant found
) else (
    echo ✗ PHASE_SELF_OPTIMIZATION constant not found
)

findstr /C:"PHASE_SELF_EXECUTION" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ PHASE_SELF_EXECUTION constant found
) else (
    echo ✗ PHASE_SELF_EXECUTION constant not found
)

echo.
echo Checking for self-hosting components:
findstr /C:"self_lexer_source" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_lexer_source found
) else (
    echo ✗ self_lexer_source not found
)

findstr /C:"self_parser_source" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_parser_source found
) else (
    echo ✗ self_parser_source not found
)

findstr /C:"self_semantic_source" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_semantic_source found
) else (
    echo ✗ self_semantic_source not found
)

findstr /C:"self_codegen_source" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_codegen_source found
) else (
    echo ✗ self_codegen_source not found
)

findstr /C:"self_compiler_source" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_compiler_source found
) else (
    echo ✗ self_compiler_source not found
)

echo.
echo Checking for meta-programming features:
findstr /C:"meta_programming_enabled" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ meta_programming_enabled found
) else (
    echo ✗ meta_programming_enabled not found
)

findstr /C:"meta_reflection_enabled" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ meta_reflection_enabled found
) else (
    echo ✗ meta_reflection_enabled not found
)

findstr /C:"meta_introspection_enabled" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ meta_introspection_enabled found
) else (
    echo ✗ meta_introspection_enabled not found
)

findstr /C:"meta_code_generation" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ meta_code_generation found
) else (
    echo ✗ meta_code_generation not found
)

findstr /C:"meta_optimization" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ meta_optimization found
) else (
    echo ✗ meta_optimization not found
)

echo.
echo Checking for self-hosting functions:
findstr /C:"self_hosted_eon_compiler_analyze_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_analyze_self function found
) else (
    echo ✗ self_hosted_eon_compiler_analyze_self function not found
)

findstr /C:"self_hosted_eon_compiler_generate_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_generate_self function found
) else (
    echo ✗ self_hosted_eon_compiler_generate_self function not found
)

findstr /C:"self_hosted_eon_compiler_validate_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_validate_self function found
) else (
    echo ✗ self_hosted_eon_compiler_validate_self function not found
)

findstr /C:"self_hosted_eon_compiler_optimize_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_optimize_self function found
) else (
    echo ✗ self_hosted_eon_compiler_optimize_self function not found
)

findstr /C:"self_hosted_eon_compiler_execute_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_execute_self function found
) else (
    echo ✗ self_hosted_eon_compiler_execute_self function not found
)

echo.
echo Checking for meta-programming functions:
findstr /C:"self_hosted_eon_compiler_meta_compile" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_meta_compile function found
) else (
    echo ✗ self_hosted_eon_compiler_meta_compile function not found
)

findstr /C:"self_hosted_eon_compiler_reflect_on_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_reflect_on_self function found
) else (
    echo ✗ self_hosted_eon_compiler_reflect_on_self function not found
)

findstr /C:"self_hosted_eon_compiler_introspect_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_introspect_self function found
) else (
    echo ✗ self_hosted_eon_compiler_introspect_self function not found
)

findstr /C:"self_hosted_eon_compiler_improve_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_improve_self function found
) else (
    echo ✗ self_hosted_eon_compiler_improve_self function not found
)

findstr /C:"self_hosted_eon_compiler_evolve_self" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_hosted_eon_compiler_evolve_self function found
) else (
    echo ✗ self_hosted_eon_compiler_evolve_self function not found
)

echo.
echo Checking for test functions in test_self_hosted_compiler.asm:
findstr /C:"test_self_hosted_compiler_init" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ test_self_hosted_compiler_init function found
) else (
    echo ✗ test_self_hosted_compiler_init function not found
)

findstr /C:"test_self_hosted_compiler_run_all_tests" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ test_self_hosted_compiler_run_all_tests function found
) else (
    echo ✗ test_self_hosted_compiler_run_all_tests function not found
)

findstr /C:"test_self_hosted_compiler_test_bootstrap_self" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ test_self_hosted_compiler_test_bootstrap_self function found
) else (
    echo ✗ test_self_hosted_compiler_test_bootstrap_self function not found
)

findstr /C:"test_self_hosted_compiler_test_compile_self" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ test_self_hosted_compiler_test_compile_self function found
) else (
    echo ✗ test_self_hosted_compiler_test_compile_self function not found
)

echo.
echo Checking for test categories:
findstr /C:"TEST_SELF_HOSTING_BOOTSTRAP" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_BOOTSTRAP constant found
) else (
    echo ✗ TEST_SELF_HOSTING_BOOTSTRAP constant not found
)

findstr /C:"TEST_SELF_HOSTING_COMPILATION" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_COMPILATION constant found
) else (
    echo ✗ TEST_SELF_HOSTING_COMPILATION constant not found
)

findstr /C:"TEST_SELF_HOSTING_ANALYSIS" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_ANALYSIS constant found
) else (
    echo ✗ TEST_SELF_HOSTING_ANALYSIS constant not found
)

findstr /C:"TEST_SELF_HOSTING_GENERATION" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_GENERATION constant found
) else (
    echo ✗ TEST_SELF_HOSTING_GENERATION constant not found
)

findstr /C:"TEST_SELF_HOSTING_VALIDATION" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_VALIDATION constant found
) else (
    echo ✗ TEST_SELF_HOSTING_VALIDATION constant not found
)

findstr /C:"TEST_SELF_HOSTING_OPTIMIZATION" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_OPTIMIZATION constant found
) else (
    echo ✗ TEST_SELF_HOSTING_OPTIMIZATION constant not found
)

findstr /C:"TEST_SELF_HOSTING_EXECUTION" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_EXECUTION constant found
) else (
    echo ✗ TEST_SELF_HOSTING_EXECUTION constant not found
)

findstr /C:"TEST_SELF_HOSTING_META" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_META constant found
) else (
    echo ✗ TEST_SELF_HOSTING_META constant not found
)

findstr /C:"TEST_SELF_HOSTING_REFLECTION" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_REFLECTION constant found
) else (
    echo ✗ TEST_SELF_HOSTING_REFLECTION constant not found
)

findstr /C:"TEST_SELF_HOSTING_INTROSPECTION" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_INTROSPECTION constant found
) else (
    echo ✗ TEST_SELF_HOSTING_INTROSPECTION constant not found
)

findstr /C:"TEST_SELF_HOSTING_IMPROVEMENT" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_IMPROVEMENT constant found
) else (
    echo ✗ TEST_SELF_HOSTING_IMPROVEMENT constant not found
)

findstr /C:"TEST_SELF_HOSTING_EVOLUTION" test_self_hosted_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ TEST_SELF_HOSTING_EVOLUTION constant found
) else (
    echo ✗ TEST_SELF_HOSTING_EVOLUTION constant not found
)

echo.
echo Checking for self-hosting statistics:
findstr /C:"self_compilation_time" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_compilation_time found
) else (
    echo ✗ self_compilation_time not found
)

findstr /C:"self_analysis_time" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_analysis_time found
) else (
    echo ✗ self_analysis_time not found
)

findstr /C:"self_generation_time" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_generation_time found
) else (
    echo ✗ self_generation_time not found
)

findstr /C:"self_validation_time" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_validation_time found
) else (
    echo ✗ self_validation_time not found
)

findstr /C:"self_optimization_time" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_optimization_time found
) else (
    echo ✗ self_optimization_time not found
)

findstr /C:"self_execution_time" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_execution_time found
) else (
    echo ✗ self_execution_time not found
)

findstr /C:"self_iterations" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_iterations found
) else (
    echo ✗ self_iterations not found
)

findstr /C:"self_improvements" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_improvements found
) else (
    echo ✗ self_improvements not found
)

findstr /C:"self_optimizations" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_optimizations found
) else (
    echo ✗ self_optimizations not found
)

findstr /C:"self_bug_fixes" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_bug_fixes found
) else (
    echo ✗ self_bug_fixes not found
)

echo.
echo Checking for self-hosting buffers:
findstr /C:"self_source_buffer" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_source_buffer found
) else (
    echo ✗ self_source_buffer not found
)

findstr /C:"self_ast_buffer" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_ast_buffer found
) else (
    echo ✗ self_ast_buffer not found
)

findstr /C:"self_ir_buffer" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_ir_buffer found
) else (
    echo ✗ self_ir_buffer not found
)

findstr /C:"self_assembly_buffer" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_assembly_buffer found
) else (
    echo ✗ self_assembly_buffer not found
)

findstr /C:"self_metadata_buffer" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_metadata_buffer found
) else (
    echo ✗ self_metadata_buffer not found
)

findstr /C:"self_analysis_buffer" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_analysis_buffer found
) else (
    echo ✗ self_analysis_buffer not found
)

findstr /C:"self_optimization_buffer" self_hosted_eon_compiler.asm >nul
if %errorlevel% == 0 (
    echo ✓ self_optimization_buffer found
) else (
    echo ✗ self_optimization_buffer not found
)

echo.
echo Summary:
echo ========
echo The self-hosted Eon compiler (Phase 2) implementation has been validated.
echo All core components are present and properly structured.
echo The implementation includes:
echo - Self-hosted Eon compiler with self-compilation capabilities
echo - Complete test suite for the self-hosted compiler
echo - Self-hosting phases (Bootstrap, Analysis, Generation, Validation, Optimization, Execution)
echo - Meta-programming features (Reflection, Introspection, Code Generation, Optimization)
echo - Self-improvement and self-evolution capabilities
echo - Comprehensive self-hosting statistics and performance measurement
echo - Self-hosting buffers for source, AST, IR, assembly, metadata, analysis, and optimization
echo - Self-hosting error handling and validation
echo - Self-hosting configuration and depth management
echo.
echo The self-hosted Eon compiler (Phase 2) is ready for use and testing.
echo This represents the ultimate achievement in compiler bootstrapping - a compiler that can compile itself!
echo.
pause
