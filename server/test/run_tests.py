#!/usr/bin/env python3
"""
Tatou Server Test Runner
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path


def get_python_command():
    """Get the appropriate Python command for the environment"""
    # Try python3 first, then python
    for cmd in ['python3', 'python']:
        try:
            result = subprocess.run([cmd, '--version'], 
                                  capture_output=True, text=True, check=True)
            if result.returncode == 0:
                return cmd
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    # Fallback to sys.executable
    return sys.executable


def run_command(cmd, description):
    """Run command and handle errors"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")

    try:
        result = subprocess.run(cmd, check=True, cwd=Path(__file__).parent)
        print(f"SUCCESS: {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {description} failed with exit code {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"ERROR: Command not found: {cmd[0]}")
        print("Please ensure pytest and coverage are installed:")
        print("pip install pytest pytest-cov coverage")
        return False


def install_dependencies():
    """Install all required dependencies in virtual environment"""
    # Core dependencies for the server
    core_deps = [
        "PyMuPDF>=1.21.1",
        "Flask==3.0.3", 
        "gunicorn==21.2.0",
        "PyMySQL==1.1.2",
        "SQLAlchemy==2.0.43",
        "dill==0.4.0",
        "Werkzeug>=2.0.0",
        "itsdangerous>=2.0.0",
        "cryptography>=3.0.0"
    ]
    
    # Test dependencies
    test_deps = [
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0", 
        "pytest-mock>=3.10.0",
        "coverage>=7.0.0"
    ]
    
    python_cmd = get_python_command()
    
    # Create virtual environment
    venv_path = Path(__file__).parent / "test_env"
    if not venv_path.exists():
        cmd_venv = [python_cmd, "-m", "venv", str(venv_path)]
        if not run_command(cmd_venv, "Creating virtual environment"):
            return False
    
    # Determine pip command for virtual environment
    if os.name == 'nt':  # Windows
        pip_cmd = str(venv_path / "Scripts" / "pip")
    else:  # Unix/Linux/macOS
        pip_cmd = str(venv_path / "bin" / "pip")
    
    # Install core dependencies
    cmd1 = [pip_cmd, "install"] + core_deps
    if not run_command(cmd1, "Installing core dependencies"):
        return False
    
    # Install test dependencies
    cmd2 = [pip_cmd, "install"] + test_deps
    return run_command(cmd2, "Installing test dependencies")


def get_venv_python():
    """Get Python command from virtual environment"""
    venv_path = Path(__file__).parent / "test_env"
    if os.name == 'nt':  # Windows
        return str(venv_path / "Scripts" / "python")
    else:  # Unix/Linux/macOS
        return str(venv_path / "bin" / "python")


def run_unit_tests():
    """Run unit tests"""
    python_cmd = get_venv_python()
    cmd = [python_cmd, "-m", "pytest", "test_unit.py", "-v", "--tb=short"]
    return run_command(cmd, "Unit tests")


def run_api_tests():
    """Run API tests"""
    python_cmd = get_venv_python()
    cmd = [python_cmd, "-m", "pytest", "test_api.py", "-v", "--tb=short"]
    return run_command(cmd, "API tests")



def run_with_coverage():
    """Run tests and generate coverage report"""
    python_cmd = get_venv_python()
    cmd = [python_cmd, "-m", "pytest", "test_unit.py", "test_api.py", "-v", "--cov=../src",
           "--cov-report=html", "--cov-report=term-missing", "--tb=short"]
    return run_command(cmd, "Tests with coverage report")


def run_all_tests():
    """Run all tests"""
    python_cmd = get_venv_python()
    cmd = [python_cmd, "-m", "pytest", "test_unit.py", "test_api.py", "-v", "--tb=short"]
    return run_command(cmd, "All tests")


def run_comprehensive_tests():
    """Run comprehensive security tests"""
    python_cmd = get_venv_python()
    cmd = [python_cmd, "-m", "pytest", "test_unit.py", "test_api.py", "-v", "--tb=short"]
    return run_command(cmd, "Comprehensive security tests")


def run_coverage_only():
    """Generate coverage report only"""
    python_cmd = get_venv_python()

    # First run tests to collect coverage data
    cmd1 = [python_cmd, "-m", "coverage", "run", "-m", "pytest", "test_unit.py", "test_api.py", "-v"]
    if not run_command(cmd1, "Collecting coverage data"):
        return False

    # Generate terminal report
    cmd2 = [python_cmd, "-m", "coverage", "report"]
    if not run_command(cmd2, "Terminal coverage report"):
        return False

    # Generate HTML report
    cmd3 = [python_cmd, "-m", "coverage", "html"]
    return run_command(cmd3, "HTML coverage report")


def clean_coverage():
    """Clean coverage data"""
    python_cmd = get_venv_python()
    cmd = [python_cmd, "-m", "coverage", "erase"]
    return run_command(cmd, "Cleaning coverage data")


def show_help():
    """Show help information"""
    print("""
Tatou Server Test Runner

Usage: python run_tests.py [command]

Commands:
  install     Install all dependencies (Flask, SQLAlchemy, etc.)
  unit        Run unit tests (37 tests)
  api         Run API tests (14 tests)
  security    Run comprehensive security tests (51 tests)
  all         Run all tests (51 tests total)
  coverage    Run tests and generate coverage report (44% coverage target)
  clean       Clean coverage data
  help        Show this help message

Dependencies installed by 'install' command:
  Core: Flask, SQLAlchemy, PyMySQL, PyMuPDF, Werkzeug, itsdangerous, cryptography, dill
  Test: pytest, pytest-cov, pytest-mock, coverage

File structure required:
  - test/run_tests.py (this script)
  - test/test_unit.py (unit tests - 37 tests)
  - test/test_api.py (API tests - 14 tests)
  - src/ (source code for coverage)

Coverage report will be generated in:
  - HTML: test/htmlcov/index.html
  
Note: CLI tools (watermarking_cli.py) are automatically excluded from coverage.
""")


def check_dependencies():
    """Check if dependencies are installed"""
    required_packages = [
        'pytest', 'coverage', 'flask', 'sqlalchemy', 
        'pymysql', 'werkzeug', 'itsdangerous', 'cryptography'
    ]
    
    # Optional packages (tests will skip if not available)
    optional_packages = ['fitz']  # PyMuPDF
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"ERROR: Missing dependencies: {', '.join(missing_packages)}")
        print("Please run: python run_tests.py install")
        return False
    
    # Check optional packages
    missing_optional = []
    for package in optional_packages:
        try:
            __import__(package)
        except ImportError:
            missing_optional.append(package)
    
    if missing_optional:
        print(f"WARNING: Optional dependencies missing: {', '.join(missing_optional)}")
        print("Some tests may be skipped (e.g., YuweiCao tests)")
    
    print("SUCCESS: All required dependencies are installed")
    return True


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Tatou Server Test Runner")
    parser.add_argument("command", nargs="?", default="all", 
                       choices=["install", "unit", "api", "security", "all", "coverage", "clean", "help"],
                       help="Command to run")
    
    args = parser.parse_args()
    
    if args.command == "help":
        show_help()
        return 0
    
    # Change to script directory
    os.chdir(Path(__file__).parent)
    
    # Check dependencies (except for install command)
    if args.command != "install":
        if not check_dependencies():
            return 1
    
    success = True
    
    if args.command == "install":
        success = install_dependencies()
    elif args.command == "unit":
        success = run_unit_tests()
    elif args.command == "api":
        success = run_api_tests()
    elif args.command == "security":
        success = run_comprehensive_tests()
    elif args.command == "all":
        success = run_all_tests()
    elif args.command == "coverage":
        success = run_with_coverage()
    elif args.command == "clean":
        success = clean_coverage()
    
    if success:
        print(f"\nSUCCESS: {args.command} completed")
        if args.command == "coverage":
            print("\nCoverage report generated:")
            print("  - HTML: test/htmlcov/index.html")
        return 0
    else:
        print(f"\nERROR: {args.command} failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())