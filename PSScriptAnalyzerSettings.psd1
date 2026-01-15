# PSScriptAnalyzerSettings.psd1
# Configuration for PSScriptAnalyzer
# Optimized for faster analysis - removed slow compatibility checks

@{
    # Exclude specific rules that are slow or not applicable
    ExcludeRules = @(
        # Slow rules - these check compatibility across PowerShell versions and can timeout
        'PSUseCompatibleCmdlets',
        'PSUseCompatibleTypes',
        'PSUseCompatibleCommands',
        'PSUseCompatibleSyntax',

        # Not applicable to this project
        'PSUseShouldProcessForStateChangingFunctions',  # We use simple functions
        'PSUseDeclaredVarsMoreThanAssignments',         # Module exports are fine
        'PSAvoidUsingWriteHost',                        # We use Write-Host for console output

        # DSC rules not applicable
        'PSDSCReturnCorrectTypesForDSCFunctions',
        'PSDSCUseIdenticalParametersForDSC',
        'PSDSCStandardDSCFunctionsInResource',
        'PSDSCUseVerboseMessageInDSCResource',
        'PSUseVerboseMessageInDSCResource'
    )

    # Only include fast, essential rules
    IncludeRules = @(
        # Security rules (critical)
        'PSAvoidUsingPlainTextPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSAvoidUsingInvokeExpression',
        'PSAvoidUsingUserNameAndPassWordParams',

        # Syntax and best practices (fast)
        'PSAvoidUsingCmdletAliases',
        'PSUseApprovedVerbs',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSAvoidDefaultValueSwitchParameter',
        'PSAvoidUsingPositionalParameters',
        'PSAvoidGlobalVars',
        'PSAvoidGlobalAliases',
        'PSAvoidUsingEmptyCatchBlock',
        'PSMisleadingBacktick',
        'PSAvoidAssignmentToAutomaticVariable',
        'PSPossibleIncorrectComparisonWithNull',
        'PSPossibleIncorrectUsageOfAssignmentOperator',
        'PSAvoidUsingBrokenHashAlgorithms',
        'PSAvoidNullOrEmptyHelpMessageAttribute',
        'PSUseCmdletCorrectly'
    )

    # Severity configuration
    Rules = @{
        'PSAvoidUsingPlainTextPassword' = @{
            Severity = 'Error'
        }
        'PSAvoidUsingConvertToSecureStringWithPlainText' = @{
            Severity = 'Error'
        }
        'PSAvoidUsingInvokeExpression' = @{
            Severity = 'Warning'
        }
        'PSAvoidDefaultValueSwitchParameter' = @{
            Severity = 'Warning'
        }
    }
}
