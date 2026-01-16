#!/usr/bin/env python3
"""
Comprehensive GUI Module Testing and Validation Script
"""
import os
import re
import json
from pathlib import Path
from collections import defaultdict
import xml.etree.ElementTree as ET

class ModuleTester:
    def __init__(self, root_dir):
        self.root_dir = Path(root_dir)
        self.results = {
            'syntax_validation': [],
            'function_exports': [],
            'dependencies': [],
            'statistics': {},
            'issues': []
        }

    def validate_syntax(self, file_path):
        """Basic PowerShell syntax validation"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            issues = []

            # Check for balanced brackets
            if content.count('{') != content.count('}'):
                issues.append("Unbalanced curly braces")
            if content.count('(') != content.count(')'):
                issues.append("Unbalanced parentheses")
            if content.count('[') != content.count(']'):
                issues.append("Unbalanced square brackets")

            # Check for unclosed strings (basic check)
            # Remove escaped quotes first
            temp_content = content.replace('`"', '').replace("``'", '')
            double_quotes = temp_content.count('"')
            single_quotes = temp_content.count("'")

            if double_quotes % 2 != 0:
                issues.append("Possible unclosed double-quoted string")
            if single_quotes % 2 != 0:
                issues.append("Possible unclosed single-quoted string")

            # Check for common PowerShell syntax patterns
            if re.search(r'function\s+\w+\s*{', content):
                # Check if functions have proper structure
                pass

            return {
                'file': file_path.name,
                'path': str(file_path),
                'status': 'PASS' if not issues else 'WARNING',
                'issues': issues
            }
        except Exception as e:
            return {
                'file': file_path.name,
                'path': str(file_path),
                'status': 'ERROR',
                'issues': [str(e)]
            }

    def extract_functions(self, file_path):
        """Extract function definitions and exports"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Find function definitions
            functions = re.findall(r'function\s+([\w-]+)\s*{', content)

            # Find Export-ModuleMember calls
            exports = re.findall(r'Export-ModuleMember\s+-Function\s+["\']?([^"\']+)["\']?', content)
            exported_funcs = []
            for exp in exports:
                # Handle comma-separated exports
                exported_funcs.extend([f.strip() for f in exp.split(',')])

            # Find dot-source imports
            imports = re.findall(r'\.\s+["\']?\$PSScriptRoot[/\\](.*?\.ps1)["\']?', content)
            imports += re.findall(r'\.\s+["\']?\$scriptPath[/\\](.*?\.ps1)["\']?', content)

            return {
                'file': file_path.name,
                'path': str(file_path),
                'functions_defined': functions,
                'functions_exported': exported_funcs,
                'imports': imports,
                'total_functions': len(functions),
                'total_exports': len(exported_funcs)
            }
        except Exception as e:
            return {
                'file': file_path.name,
                'path': str(file_path),
                'error': str(e)
            }

    def count_lines(self, file_path):
        """Count lines of code"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            total = len(lines)
            code = 0
            comments = 0
            blank = 0

            in_comment_block = False

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    blank += 1
                elif stripped.startswith('<#'):
                    in_comment_block = True
                    comments += 1
                elif stripped.startswith('#>'):
                    in_comment_block = False
                    comments += 1
                elif in_comment_block:
                    comments += 1
                elif stripped.startswith('#'):
                    comments += 1
                else:
                    code += 1

            return {
                'total': total,
                'code': code,
                'comments': comments,
                'blank': blank
            }
        except Exception as e:
            return {'error': str(e)}

    def validate_xaml(self, xaml_path):
        """Validate XAML file"""
        try:
            tree = ET.parse(xaml_path)
            root = tree.getroot()

            # Extract all x:Name attributes
            ns = {'x': 'http://schemas.microsoft.com/winfx/2006/xaml'}
            named_elements = []

            for elem in root.iter():
                name = elem.get('{http://schemas.microsoft.com/winfx/2006/xaml}Name')
                if name:
                    named_elements.append({
                        'name': name,
                        'type': elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                    })

            return {
                'valid': True,
                'named_elements': named_elements,
                'total_named_elements': len(named_elements)
            }
        except ET.ParseError as e:
            return {
                'valid': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }

    def analyze_dependencies(self):
        """Analyze module dependencies"""
        dependencies = {}

        ps1_files = list(self.root_dir.rglob('*.ps1'))

        for file_path in ps1_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Find dot-source imports
                imports = re.findall(r'\.\s+["\']?\$(?:PSScriptRoot|scriptPath)[/\\](.*?\.ps1)["\']?', content)

                rel_path = file_path.relative_to(self.root_dir)
                dependencies[str(rel_path)] = imports
            except Exception:
                pass

        return dependencies

    def run_all_tests(self):
        """Run all validation tests"""
        print("=" * 80)
        print("COMPREHENSIVE GUI MODULE TESTING & VALIDATION")
        print("=" * 80)
        print()

        # Find all PowerShell files
        ps1_files = sorted(list(self.root_dir.rglob('*.ps1')))
        xaml_files = list(self.root_dir.rglob('*.xaml'))

        print(f"Found {len(ps1_files)} PowerShell files")
        print(f"Found {len(xaml_files)} XAML files")
        print()

        # 1. Syntax Validation
        print("=" * 80)
        print("1. SYNTAX VALIDATION")
        print("=" * 80)
        print()

        syntax_results = []
        for file_path in ps1_files:
            result = self.validate_syntax(file_path)
            syntax_results.append(result)

            status_color = {
                'PASS': '✓',
                'WARNING': '⚠',
                'ERROR': '✗'
            }

            print(f"{status_color.get(result['status'], '?')} {result['file']:<50} [{result['status']}]")
            if result['issues']:
                for issue in result['issues']:
                    print(f"    - {issue}")

        passed = sum(1 for r in syntax_results if r['status'] == 'PASS')
        warnings = sum(1 for r in syntax_results if r['status'] == 'WARNING')
        errors = sum(1 for r in syntax_results if r['status'] == 'ERROR')

        print()
        print(f"Summary: {passed} PASS, {warnings} WARNING, {errors} ERROR")
        print()

        # 2. Function Export Validation
        print("=" * 80)
        print("2. FUNCTION EXPORT VALIDATION")
        print("=" * 80)
        print()

        function_results = []
        total_functions = 0
        total_exports = 0

        for file_path in ps1_files:
            result = self.extract_functions(file_path)
            function_results.append(result)

            if 'total_functions' in result:
                total_functions += result['total_functions']
                total_exports += result['total_exports']

                print(f"{result['file']:<50} Functions: {result['total_functions']:<3} Exports: {result['total_exports']:<3}")

                # Check for unexported functions
                if result['functions_defined'] and result['functions_exported']:
                    unexported = set(result['functions_defined']) - set(result['functions_exported'])
                    if unexported:
                        print(f"    ⚠ Unexported functions: {', '.join(unexported)}")

        print()
        print(f"Total Functions Defined: {total_functions}")
        print(f"Total Functions Exported: {total_exports}")
        print()

        # 3. XAML Validation
        print("=" * 80)
        print("3. XAML VALIDATION")
        print("=" * 80)
        print()

        for xaml_path in xaml_files:
            result = self.validate_xaml(xaml_path)

            if result['valid']:
                print(f"✓ {xaml_path.name} - Valid XML")
                print(f"  Named elements: {result['total_named_elements']}")
                print()
                print("  Controls with x:Name:")
                for elem in result['named_elements'][:10]:  # Show first 10
                    print(f"    - {elem['name']:<40} ({elem['type']})")
                if len(result['named_elements']) > 10:
                    print(f"    ... and {len(result['named_elements']) - 10} more")
            else:
                print(f"✗ {xaml_path.name} - Invalid XML")
                print(f"  Error: {result['error']}")

        print()

        # 4. Code Statistics
        print("=" * 80)
        print("4. CODE STATISTICS")
        print("=" * 80)
        print()

        total_stats = {
            'total': 0,
            'code': 0,
            'comments': 0,
            'blank': 0
        }

        for file_path in ps1_files:
            stats = self.count_lines(file_path)
            if 'error' not in stats:
                for key in total_stats:
                    total_stats[key] += stats[key]

        print(f"Total Lines:        {total_stats['total']:,}")
        print(f"Code Lines:         {total_stats['code']:,}")
        print(f"Comment Lines:      {total_stats['comments']:,}")
        print(f"Blank Lines:        {total_stats['blank']:,}")
        print(f"Code Percentage:    {(total_stats['code']/total_stats['total']*100):.1f}%")
        print()

        # 5. Module Dependencies
        print("=" * 80)
        print("5. MODULE DEPENDENCIES")
        print("=" * 80)
        print()

        dependencies = self.analyze_dependencies()

        for module, imports in sorted(dependencies.items()):
            if imports:
                print(f"{module}")
                for imp in imports:
                    print(f"  └─ {imp}")

        print()

        # 6. File Organization
        print("=" * 80)
        print("6. FILE ORGANIZATION")
        print("=" * 80)
        print()

        categories = defaultdict(list)
        for file_path in ps1_files:
            category = file_path.parent.name
            categories[category].append(file_path.name)

        for category, files in sorted(categories.items()):
            print(f"\n{category}/ ({len(files)} files)")
            for f in sorted(files):
                print(f"  - {f}")

        print()

        # Summary
        print("=" * 80)
        print("OVERALL SUMMARY")
        print("=" * 80)
        print()
        print(f"Total Modules:           {len(ps1_files)}")
        print(f"Total Functions:         {total_functions}")
        print(f"Total Exported Functions: {total_exports}")
        print(f"Total Lines of Code:     {total_stats['code']:,}")
        print(f"Syntax Issues:           {warnings + errors}")
        print()

        # Store results
        self.results = {
            'syntax_validation': syntax_results,
            'function_exports': function_results,
            'dependencies': dependencies,
            'statistics': total_stats,
            'total_modules': len(ps1_files),
            'total_functions': total_functions,
            'total_exports': total_exports
        }

        return self.results

if __name__ == '__main__':
    tester = ModuleTester('/home/user/GA-AppLocker_FINAL/src/GUI')
    results = tester.run_all_tests()
