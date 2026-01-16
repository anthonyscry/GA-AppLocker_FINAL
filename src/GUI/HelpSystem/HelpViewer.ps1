<#
.SYNOPSIS
    Help viewer display logic

.DESCRIPTION
    Provides UI functions for displaying help content in the help panel
    and searching across help topics.

.NOTES
    Author: GA-AppLocker Team
    Version: 1.2.5
#>

function Show-HelpTopic {
    <#
    .SYNOPSIS
        Displays help content in the help panel

    .DESCRIPTION
        Retrieves and displays help content for the specified topic in the help panel UI control.

    .PARAMETER HelpPanel
        The WPF TextBox control where help content will be displayed

    .PARAMETER Topic
        The help topic to display (Workflow, Rules, Troubleshooting, WhatsNew, PolicyGuide)

    .EXAMPLE
        Show-HelpTopic -HelpPanel $HelpTextBox -Topic "Workflow"
        Displays the workflow guide in the help panel
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Controls.TextBox]$HelpPanel,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Workflow", "Rules", "Troubleshooting", "WhatsNew", "PolicyGuide")]
        [string]$Topic
    )

    try {
        # Get help content for the topic
        $content = Get-HelpContent -Topic $Topic

        # Display in help panel
        if ($null -ne $HelpPanel) {
            $HelpPanel.Text = $content
            $HelpPanel.ScrollToHome()
        }

        Write-Verbose "Displayed help topic: $Topic"
    }
    catch {
        Write-Warning "Failed to display help topic '$Topic': $_"
        if ($null -ne $HelpPanel) {
            $HelpPanel.Text = "Error loading help content: $_"
        }
    }
}

function Search-HelpContent {
    <#
    .SYNOPSIS
        Searches across all help topics

    .DESCRIPTION
        Searches all help topics for the specified search term and returns matching results
        with context showing where the term appears.

    .PARAMETER SearchTerm
        The term to search for across all help topics

    .PARAMETER ContextLines
        Number of lines of context to show before and after each match (default: 2)

    .OUTPUTS
        Returns a collection of search results with topic name, line number, and context

    .EXAMPLE
        Search-HelpContent -SearchTerm "audit mode"
        Searches all help topics for "audit mode" and returns matching results
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SearchTerm,

        [Parameter(Mandatory=$false)]
        [int]$ContextLines = 2
    )

    if ([string]::IsNullOrWhiteSpace($SearchTerm)) {
        Write-Warning "Search term cannot be empty"
        return @()
    }

    $results = @()
    $topics = @("Workflow", "Rules", "Troubleshooting", "WhatsNew", "PolicyGuide")

    foreach ($topic in $topics) {
        try {
            $content = Get-HelpContent -Topic $topic
            $lines = $content -split "`n"

            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match [regex]::Escape($SearchTerm)) {
                    # Get context lines
                    $startLine = [Math]::Max(0, $i - $ContextLines)
                    $endLine = [Math]::Min($lines.Count - 1, $i + $ContextLines)

                    $contextText = @()
                    for ($j = $startLine; $j -le $endLine; $j++) {
                        $prefix = if ($j -eq $i) { ">>> " } else { "    " }
                        $contextText += "$prefix$($lines[$j])"
                    }

                    $results += [PSCustomObject]@{
                        Topic = $topic
                        LineNumber = $i + 1
                        MatchLine = $lines[$i].Trim()
                        Context = ($contextText -join "`n")
                    }
                }
            }
        }
        catch {
            Write-Warning "Error searching topic '$topic': $_"
        }
    }

    return $results
}

function Format-SearchResults {
    <#
    .SYNOPSIS
        Formats search results for display

    .DESCRIPTION
        Takes search results and formats them as readable text for display in the help panel.

    .PARAMETER Results
        Array of search result objects from Search-HelpContent

    .PARAMETER SearchTerm
        The original search term (for display in header)

    .OUTPUTS
        Returns formatted string ready for display

    .EXAMPLE
        $results = Search-HelpContent -SearchTerm "GPO"
        Format-SearchResults -Results $results -SearchTerm "GPO"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Results,

        [Parameter(Mandatory=$true)]
        [string]$SearchTerm
    )

    if ($Results.Count -eq 0) {
        return "No results found for: '$SearchTerm'"
    }

    $output = "=== SEARCH RESULTS ===`n"
    $output += "Search term: '$SearchTerm'`n"
    $output += "Found $($Results.Count) match(es)`n"
    $output += "`n" + ("=" * 70) + "`n`n"

    foreach ($result in $Results) {
        $output += "TOPIC: $($result.Topic) (Line $($result.LineNumber))`n"
        $output += "$($result.Context)`n"
        $output += "`n" + ("-" * 70) + "`n`n"
    }

    return $output
}

function Show-HelpSearch {
    <#
    .SYNOPSIS
        Performs search and displays results in help panel

    .DESCRIPTION
        Combines Search-HelpContent and Format-SearchResults to search and display results.

    .PARAMETER HelpPanel
        The WPF TextBox control where search results will be displayed

    .PARAMETER SearchTerm
        The term to search for

    .EXAMPLE
        Show-HelpSearch -HelpPanel $HelpTextBox -SearchTerm "audit"
        Searches for "audit" and displays formatted results
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Controls.TextBox]$HelpPanel,

        [Parameter(Mandatory=$true)]
        [string]$SearchTerm
    )

    try {
        $results = Search-HelpContent -SearchTerm $SearchTerm
        $formattedResults = Format-SearchResults -Results $results -SearchTerm $SearchTerm

        if ($null -ne $HelpPanel) {
            $HelpPanel.Text = $formattedResults
            $HelpPanel.ScrollToHome()
        }

        Write-Verbose "Search completed: $($results.Count) results found"
    }
    catch {
        Write-Warning "Search failed: $_"
        if ($null -ne $HelpPanel) {
            $HelpPanel.Text = "Search error: $_"
        }
    }
}

Export-ModuleMember -Function Show-HelpTopic, Search-HelpContent, Format-SearchResults, Show-HelpSearch
