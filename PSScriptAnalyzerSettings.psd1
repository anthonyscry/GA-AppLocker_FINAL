# PSScriptAnalyzerSettings.psd1
# Configuration for PSScriptAnalyzer

@{
    # Exclude specific rules
    ExcludeRules = @(
        # PSUseShouldProcessForStateChangingFunctions - We use simple functions
        'PSUseShouldProcessForStateChangingFunctions',

        # PSUseDeclaredVarsMoreThanAssignments - Module exports are fine
        'PSUseDeclaredVarsMoreThanAssignments',

        # PSAvoidUsingWriteHost - We use Write-Host for console output in scripts
        'PSAvoidUsingWriteHost'
    )

    # Include specific rules (optional - defaults to all)
    IncludeRules = @(
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingPlainTextPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSAvoidUsingInvokeExpression',
        'PSUseApprovedVerbs',
        'PSUseSingularNouns',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSMissingModuleManifestField',
        'PSAvoidDefaultValueSwitchParameter',
        'PSUseOutputTypeCorrectly',
        'PSCmdletShouldProcess',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingPositionalParameters',
        'PSAvoidGlobalVars',
        'PSAvoidUsingUserNameAndPassWordParams',
        'PSAvoidUsingWMICmdlet',
        'PSAvoidUsingEmptyCatchBlock',
        'PSAvoidGlobalAliases',
        'PSDSCReturnCorrectTypesForDSCFunctions',
        'PSDSCUseIdenticalParametersForDSC',
        'PSDSCStandardDSCFunctionsInResource',
        'PSDSCUseVerboseMessageInDSCResource',
        'PSUseCompatibleCmdlets',
        'PSUseCompatibleTypes',
        'PSUseCompatibleCommands',
        'PSMisleadingBacktick',
        'PSAvoidAssignmentToAutomaticVariable',
        'PSAvoidAssignmentToReadOnlyAttribute',
        'PSAvoidInvokeExpression',
        'PSAvoidMultipleTypeAttributes',
        'PSPossibleIncorrectComparisonWithNull',
        'PSPossibleIncorrectUsageOfAssignmentOperator',
        'PSUseBOMForUnicodeEncodedFile',
        'PSAvoidUsingBrokenHashAlgorithms',
        'PSAvoidUsingDeprecatedManifestFields',
        'PSAvoidUsingObsoleteCmdlets',
        'PSAvoidUsingInvokeExpression',
        'PSAvoidNullOrEmptyHelpMessageAttribute',
        'PSMissingModuleManifestField',
        'PSUseCmdletCorrectly',
        'PSUseCorrectCasing',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSPossibleIncorrectUsageOfAssignmentOperator',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseToExportFieldsInManifest',
        'PSUseUTF8EncodingForHelpFile',
        'PSUseVerboseMessageInDSCResource'
    )

    # Severity levels for rules
    # Error: Stop processing
    # Warning: Show warning
    # Information: Show info
    # None: Ignore
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
        'PSAvoidUsingWriteHost' = @{
            Severity = 'Information'
        }
    }
}
