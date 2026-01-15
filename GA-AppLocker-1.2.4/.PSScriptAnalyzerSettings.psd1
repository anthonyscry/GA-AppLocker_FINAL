# PSScriptAnalyzer Settings for GA-AppLocker
# Apply consistent code quality rules across the entire codebase

@{
    # Severity levels to include
    Severity = @('Error', 'Warning')

    # Rules to exclude (with justification)
    ExcludeRules = @(
        # Write-Host is appropriate for CLI tools with colored feedback
        'PSAvoidUsingWriteHost'
    )

    # Rules to include explicitly (security + quality)
    IncludeRules = @(
        # Security rules
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSAvoidUsingUserNameAndPasswordParams',
        'PSAvoidUsingInvokeExpression',

        # Best practices
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingPositionalParameters',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseApprovedVerbs',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSMissingModuleManifestField',
        'PSAvoidDefaultValueSwitchParameter',
        'PSAvoidGlobalVars',
        'PSAvoidUsingEmptyCatchBlock',
        'PSUseCmdletCorrectly',
        'PSUseOutputTypeCorrectly',

        # Formatting rules
        'PSAvoidTrailingWhitespace',
        'PSUseConsistentIndentation',
        'PSUseConsistentWhitespace',
        'PSPlaceOpenBrace',
        'PSPlaceCloseBrace'
    )

    # Custom rule configurations
    Rules = @{
        PSUseConsistentIndentation = @{
            Enable = $true
            IndentationSize = 4
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            Kind = 'space'
        }

        PSUseConsistentWhitespace = @{
            Enable = $true
            CheckInnerBrace = $true
            CheckOpenBrace = $true
            CheckOpenParen = $true
            CheckOperator = $true
            CheckPipe = $true
            CheckPipeForRedundantWhitespace = $true
            CheckSeparator = $true
            CheckParameter = $false
            IgnoreAssignmentOperatorInsideHashTable = $true
        }

        PSPlaceOpenBrace = @{
            Enable = $true
            OnSameLine = $true
            NewLineAfter = $true
            IgnoreOneLineBlock = $true
        }

        PSPlaceCloseBrace = @{
            Enable = $true
            NewLineAfter = $true
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore = $false
        }

        PSAlignAssignmentStatement = @{
            Enable = $false
            CheckHashtable = $false
        }

        PSProvideCommentHelp = @{
            Enable = $true
            ExportedOnly = $true
            BlockComment = $true
            VSCodeSnippetCorrection = $false
            Placement = 'begin'
        }
    }
}
