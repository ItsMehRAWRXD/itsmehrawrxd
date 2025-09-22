#!/bin/bash

# build.sh - Build script for RawrZApp compiler suite
# Provides easy access to CMake build system with various configurations

set -e  # Exit on error

# Default values
BUILD_TYPE="Release"
BUILD_DIR="build"
CLEAN=false
TESTS=false
BENCHMARK=false
INSTALL=false
PACKAGE=false
DOCS=false
VERBOSE=false
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show usage information
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build script for RawrZApp compiler suite

OPTIONS:
    -h, --help          Show this help message
    -t, --type TYPE     Build type: Debug, Release, RelWithDebInfo, MinSizeRel (default: Release)
    -d, --dir DIR       Build directory (default: build)
    -c, --clean         Clean build directory before building
    -j, --jobs N        Number of parallel jobs (default: auto-detected)
    -T, --tests         Run tests after building
    -b, --benchmark     Run benchmarks after building
    -i, --install       Install after building
    -p, --package       Create package after building
    --docs              Generate documentation
    -v, --verbose       Verbose build output
    --asan              Enable AddressSanitizer
    --tsan              Enable ThreadSanitizer
    --ubsan             Enable UndefinedBehaviorSanitizer
    --coverage          Enable code coverage
    --static            Build static executables

EXAMPLES:
    $0                          # Build release version
    $0 -t Debug -T              # Build debug version and run tests
    $0 -c -t Release -i         # Clean, build release, and install
    $0 --asan -t Debug -T       # Build debug with AddressSanitizer and run tests
    $0 --coverage -T            # Build with coverage and run tests
    $0 -b -p                    # Build, benchmark, and create package

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -t|--type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -d|--dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        -T|--tests)
            TESTS=true
            shift
            ;;
        -b|--benchmark)
            BENCHMARK=true
            shift
            ;;
        -i|--install)
            INSTALL=true
            shift
            ;;
        -p|--package)
            PACKAGE=true
            shift
            ;;
        --docs)
            DOCS=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --asan)
            CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_ASAN=ON"
            shift
            ;;
        --tsan)
            CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_TSAN=ON"
            shift
            ;;
        --ubsan)
            CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_UBSAN=ON"
            shift
            ;;
        --coverage)
            CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_COVERAGE=ON"
            shift
            ;;
        --static)
            CMAKE_OPTIONS="$CMAKE_OPTIONS -DSTATIC_BUILD=ON"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate build type
case $BUILD_TYPE in
    Debug|Release|RelWithDebInfo|MinSizeRel)
        ;;
    *)
        print_error "Invalid build type: $BUILD_TYPE"
        print_info "Valid types: Debug, Release, RelWithDebInfo, MinSizeRel"
        exit 1
        ;;
esac

# Print build configuration
print_info "RawrZApp Build Configuration:"
print_info "  Build Type: $BUILD_TYPE"
print_info "  Build Directory: $BUILD_DIR"
print_info "  Parallel Jobs: $JOBS"
print_info "  Clean Build: $CLEAN"
print_info "  Run Tests: $TESTS"
print_info "  Run Benchmarks: $BENCHMARK"
print_info "  Install: $INSTALL"
print_info "  Create Package: $PACKAGE"
print_info "  Generate Docs: $DOCS"
if [[ -n "$CMAKE_OPTIONS" ]]; then
    print_info "  CMake Options: $CMAKE_OPTIONS"
fi

# Clean build directory if requested
if [[ "$CLEAN" == true ]]; then
    print_info "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with CMake
print_info "Configuring with CMake..."
CMAKE_CMD="cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE $CMAKE_OPTIONS .."
if [[ "$VERBOSE" == true ]]; then
    print_info "Running: $CMAKE_CMD"
fi
eval $CMAKE_CMD

# Build
print_info "Building..."
BUILD_CMD="cmake --build . --config $BUILD_TYPE -j $JOBS"
if [[ "$VERBOSE" == true ]]; then
    BUILD_CMD="$BUILD_CMD --verbose"
    print_info "Running: $BUILD_CMD"
fi
eval $BUILD_CMD

print_success "Build completed successfully!"

# Run tests if requested
if [[ "$TESTS" == true ]]; then
    print_info "Running tests..."
    if cmake --build . --target run_tests; then
        print_success "All tests passed!"
    else
        print_error "Some tests failed!"
        exit 1
    fi
fi

# Run benchmarks if requested
if [[ "$BENCHMARK" == true ]]; then
    print_info "Running benchmarks..."
    if cmake --build . --target benchmark; then
        print_success "Benchmarks completed!"
    else
        print_warning "Benchmarks failed or not available"
    fi
fi

# Generate documentation if requested
if [[ "$DOCS" == true ]]; then
    print_info "Generating documentation..."
    if cmake --build . --target docs; then
        print_success "Documentation generated!"
    else
        print_warning "Documentation generation failed or Doxygen not available"
    fi
fi

# Install if requested
if [[ "$INSTALL" == true ]]; then
    print_info "Installing..."
    if cmake --install .; then
        print_success "Installation completed!"
    else
        print_error "Installation failed!"
        exit 1
    fi
fi

# Create package if requested
if [[ "$PACKAGE" == true ]]; then
    print_info "Creating package..."
    if cpack; then
        print_success "Package created successfully!"
        print_info "Package files:"
        ls -la *.tar.gz *.zip *.deb *.rpm *.dmg 2>/dev/null || true
    else
        print_error "Package creation failed!"
        exit 1
    fi
fi

print_success "Build script completed successfully!"
print_info "Build artifacts are in: $BUILD_DIR"
print_info ""
print_info "Available executables:"
print_info "  - reverser_lexer: Reverser language lexer"
print_info "  - reverser_parser: Reverser language parser"
print_info "  - reverser_runtime_test: Reverser runtime tests"
print_info "  - reverser_vtable_test: Reverser vtable tests"
print_info "  - reverser_bootstrap: Reverser self-hosting compiler"
print_info "  - eon_compiler: Eon compiler (C version)"
print_info "  - eon_llvm_compiler: Eon LLVM compiler (C version)"
print_info ""
print_info "To run a quick test:"
print_info "  cd $BUILD_DIR && ./reverser_lexer"
print_info "  cd $BUILD_DIR && ./eon_compiler ../test_program.eon"