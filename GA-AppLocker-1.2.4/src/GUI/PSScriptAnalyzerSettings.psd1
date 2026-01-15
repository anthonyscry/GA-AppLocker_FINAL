@{
    # Severity levels to include
    Severity = @('Error', 'Warning')

    # Rules to exclude (with justification)
    ExcludeRules = @(
        # Write-Host is appropriate for GUI console output and colored feedback
        'PSAvoidUsingWriteHost',
        # GUI code uses scriptblock-reset indentation style which PSScriptAnalyzer doesn't understand
        'PSUseConsistentIndentation',
        # Whitespace inside event handler scriptblocks follows different conventions
        'PSUseConsistentWhitespace',
        # BOM is not required for UTF-8 files in modern systems
        'PSUseBOMForUnicodeEncodedFile'
    )

    # Rules to include explicitly
    IncludeRules = @(
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingPositionalParameters',
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSAvoidUsingUserNameAndPasswordParams',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseApprovedVerbs',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSMissingModuleManifestField',
        'PSAvoidDefaultValueSwitchParameter',
        'PSAvoidGlobalVars',
        'PSAvoidUsingEmptyCatchBlock',
        'PSAvoidUsingInvokeExpression',
        'PSUseCmdletCorrectly',
        'PSUseOutputTypeCorrectly',
        'PSAvoidTrailingWhitespace'
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
