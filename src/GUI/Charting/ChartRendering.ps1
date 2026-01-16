<#
.SYNOPSIS
    Chart rendering for dashboard visualizations

.DESCRIPTION
    Provides chart rendering functions for pie charts, gauges, and bar charts
    used in the dashboard panel.

.NOTES
    Author: GA-AppLocker Team
    Version: 1.2.5
#>

function Update-Charts {
    <#
    .SYNOPSIS
        Updates all dashboard charts with new data

    .DESCRIPTION
        Renders pie charts, gauge charts, and bar charts with the provided data.

    .PARAMETER Allowed
        Number of allowed events

    .PARAMETER Audited
        Number of audited events

    .PARAMETER Blocked
        Number of blocked events

    .PARAMETER HealthScore
        Policy health score (0-100)

    .EXAMPLE
        Update-Charts -Allowed 150 -Audited 25 -Blocked 10 -HealthScore 85
    #>
    param(
        [Parameter(Mandatory=$false)]
        [int]$Allowed = 0,

        [Parameter(Mandatory=$false)]
        [int]$Audited = 0,

        [Parameter(Mandatory=$false)]
        [int]$Blocked = 0,

        [Parameter(Mandatory=$false)]
        [int]$HealthScore = 0
    )

    # Skip if chart controls are not available
    if ($null -eq $PieAllowed -or $null -eq $PieAudited -or $null -eq $PieBlocked -or
        $null -eq $GaugeBackground -or $null -eq $GaugeFill) {
        return
    }

    $total = $Allowed + $Audited + $Blocked

    # Update Pie Chart
    if ($total -gt 0) {
        $centerX = 100
        $centerY = 100
        $radius = 90

        $currentAngle = -90
        $allowedAngle = ($Allowed / $total) * 360
        $auditedAngle = ($Audited / $total) * 360
        $blockedAngle = ($Blocked / $total) * 360

        # Allowed slice
        if ($Allowed -gt 0) {
            $endAngle = $currentAngle + $allowedAngle
            $allowedPath = Get-PieSlicePath -CenterX $centerX -CenterY $centerY -Radius $radius -StartAngle $currentAngle -EndAngle $endAngle
            if ($null -ne $PieAllowed) { $PieAllowed.Data = $allowedPath }
            $currentAngle = $endAngle
        } else {
            if ($null -ne $PieAllowed) { $PieAllowed.Data = "" }
        }

        # Audited slice
        if ($Audited -gt 0) {
            $endAngle = $currentAngle + $auditedAngle
            $auditedPath = Get-PieSlicePath -CenterX $centerX -CenterY $centerY -Radius $radius -StartAngle $currentAngle -EndAngle $endAngle
            if ($null -ne $PieAudited) { $PieAudited.Data = $auditedPath }
            $currentAngle = $endAngle
        } else {
            if ($null -ne $PieAudited) { $PieAudited.Data = "" }
        }

        # Blocked slice
        if ($Blocked -gt 0) {
            $endAngle = $currentAngle + $blockedAngle
            $blockedPath = Get-PieSlicePath -CenterX $centerX -CenterY $centerY -Radius $radius -StartAngle $currentAngle -EndAngle $endAngle
            if ($null -ne $PieBlocked) { $PieBlocked.Data = $blockedPath }
        } else {
            if ($null -ne $PieBlocked) { $PieBlocked.Data = "" }
        }
    } else {
        if ($null -ne $PieAllowed) { $PieAllowed.Data = "" }
        if ($null -ne $PieAudited) { $PieAudited.Data = "" }
        if ($null -ne $PieBlocked) { $PieBlocked.Data = "" }
    }

    # Update Gauge
    Render-GaugeChart -Score $HealthScore

    # Update Machine Type Bars (placeholder data - would need actual AD query)
    $workstations = 42
    $servers = 15
    $dcs = 3
    $maxMachines = [Math]::Max($workstations, [Math]::Max($servers, $dcs))

    if ($maxMachines -gt 0) {
        $wsHeight = ($workstations / $maxMachines) * 120
        $svHeight = ($servers / $maxMachines) * 120
        $dcHeight = ($dcs / $maxMachines) * 120

        if ($null -ne $BarWorkstations) { $BarWorkstations.Height = $wsHeight }
        if ($null -ne $BarServers) { $BarServers.Height = $svHeight }
        if ($null -ne $BarDCs) { $BarDCs.Height = $dcHeight }

        if ($null -ne $LabelWorkstations) { $LabelWorkstations.Text = $workstations.ToString() }
        if ($null -ne $LabelServers) { $LabelServers.Text = $servers.ToString() }
        if ($null -ne $LabelDCs) { $LabelDCs.Text = $dcs.ToString() }
    }

    if ($null -ne $TotalMachinesLabel) {
        $TotalMachinesLabel.Text = "Total: $($workstations + $servers + $dcs) machines"
    }

    # Update Trend Chart
    Render-TrendChart
}

function Get-PieSlicePath {
    <#
    .SYNOPSIS
        Calculates SVG path for a pie chart slice

    .DESCRIPTION
        Generates the path data string for rendering a pie slice in WPF.

    .PARAMETER CenterX
        X coordinate of pie chart center

    .PARAMETER CenterY
        Y coordinate of pie chart center

    .PARAMETER Radius
        Radius of the pie chart

    .PARAMETER StartAngle
        Starting angle in degrees (0 = right, 90 = bottom, -90 = top)

    .PARAMETER EndAngle
        Ending angle in degrees

    .OUTPUTS
        Returns SVG path string for the pie slice

    .EXAMPLE
        Get-PieSlicePath -CenterX 100 -CenterY 100 -Radius 90 -StartAngle -90 -EndAngle 90
    #>
    param(
        [Parameter(Mandatory=$true)]
        [double]$CenterX,

        [Parameter(Mandatory=$true)]
        [double]$CenterY,

        [Parameter(Mandatory=$true)]
        [double]$Radius,

        [Parameter(Mandatory=$true)]
        [double]$StartAngle,

        [Parameter(Mandatory=$true)]
        [double]$EndAngle
    )

    $startRad = ([Math]::PI / 180) * $StartAngle
    $endRad = ([Math]::PI / 180) * $EndAngle

    $startX = $CenterX + $Radius * [Math]::Cos($startRad)
    $startY = $CenterY + $Radius * [Math]::Sin($startRad)
    $endX = $CenterX + $Radius * [Math]::Cos($endRad)
    $endY = $CenterY + $Radius * [Math]::Sin($endRad)

    $largeArc = if ($EndAngle - $StartAngle -gt 180) { 1 } else { 0 }

    if ($EndAngle - $StartAngle -ge 360) {
        return "M $CenterX,$CenterY m -$Radius,0 a $Radius,$Radius 0 1,0 $($Radius*2),0 a $Radius,$Radius 0 1,0 -$($Radius*2),0"
    }

    return "M $CenterX,$CenterY L $startX,$startY A $Radius,$Radius 0 $largeArc,1 $endX,$endY Z"
}

function Render-GaugeChart {
    <#
    .SYNOPSIS
        Renders a circular gauge chart

    .DESCRIPTION
        Creates a semi-circular gauge visualization showing a score from 0-100.

    .PARAMETER Score
        The score to display (0-100)

    .PARAMETER Label
        Optional label for the gauge

    .EXAMPLE
        Render-GaugeChart -Score 85 -Label "Policy Health"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateRange(0, 100)]
        [int]$Score,

        [Parameter(Mandatory=$false)]
        [string]$Label = ""
    )

    $gaugeWidth = 180
    $gaugeHeight = 90
    $gaugeRadius = 80

    # Background arc (semi-circle)
    $bgStart = [System.Windows.Point]::new(10, 90)
    $bgEnd = [System.Windows.Point]::new(190, 90)
    $bgLargeArc = 0
    $bgPath = "M $([Math]::Round($bgStart.X)) $([Math]::Round($bgStart.Y)) A $gaugeRadius $gaugeRadius 0 $bgLargeArc 1 $([Math]::Round($bgEnd.X)) $([Math]::Round($bgEnd.Y)) L 10 90"
    if ($null -ne $GaugeBackground) { $GaugeBackground.Data = $bgPath }

    # Fill arc based on health score
    if ($Score -gt 0) {
        $scoreRatio = $Score / 100
        $fillAngle = 180 * $scoreRatio
        $startRad = ([Math]::PI / 180) * 0
        $endRad = ([Math]::PI / 180) * $fillAngle

        $fillStart = [System.Windows.Point]::new(10 + $gaugeRadius * [Math]::Cos($startRad), 90 - $gaugeRadius * [Math]::Sin($startRad))
        $fillEnd = [System.Windows.Point]::new(10 + $gaugeRadius * [Math]::Cos($endRad), 90 - $gaugeRadius * [Math]::Sin($endRad))
        $fillLargeArc = if ($fillAngle -gt 180) { 1 } else { 0 }

        $fillPath = "M $([Math]::Round($fillStart.X)) $([Math]::Round($fillStart.Y)) A $gaugeRadius $gaugeRadius 0 $fillLargeArc 1 $([Math]::Round($fillEnd.X)) $([Math]::Round($fillEnd.Y)) L 10 90"
        if ($null -ne $GaugeFill) { $GaugeFill.Data = $fillPath }

        # Color based on score
        $gaugeColor = if ($Score -ge 75) { "#3FB950" } elseif ($Score -ge 50) { "#D29922" } else { "#F85149" }
        if ($null -ne $GaugeFill) { $GaugeFill.Fill = $gaugeColor }
    } else {
        if ($null -ne $GaugeFill) { $GaugeFill.Data = "" }
    }

    if ($null -ne $GaugeScore) { $GaugeScore.Text = $Score.ToString() }

    $gaugeLabel = if ($Score -eq 100) { "Fully Configured" }
                  elseif ($Score -ge 75) { "Well Configured" }
                  elseif ($Score -ge 50) { "Partially Configured" }
                  elseif ($Score -gt 0) { "Minimal Configuration" }
                  else { "No Policy Configured" }

    if ($null -ne $GaugeLabel) { $GaugeLabel.Text = $gaugeLabel }
}

function Render-PieChart {
    <#
    .SYNOPSIS
        Renders a pie chart

    .DESCRIPTION
        Creates a pie chart visualization from the provided data.

    .PARAMETER Canvas
        The WPF canvas control to render on

    .PARAMETER Data
        Hashtable of data values (key = category, value = count)

    .PARAMETER Colors
        Hashtable of colors for each category

    .EXAMPLE
        Render-PieChart -Canvas $ChartCanvas -Data @{Allowed=100; Blocked=20} -Colors @{Allowed="#3FB950"; Blocked="#F85149"}
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Canvas,

        [Parameter(Mandatory=$true)]
        [hashtable]$Data,

        [Parameter(Mandatory=$true)]
        [hashtable]$Colors
    )

    $centerX = 100
    $centerY = 100
    $radius = 90

    $total = ($Data.Values | Measure-Object -Sum).Sum
    if ($total -eq 0) { return }

    $currentAngle = -90

    foreach ($category in $Data.Keys) {
        $value = $Data[$category]
        if ($value -le 0) { continue }

        $sliceAngle = ($value / $total) * 360
        $endAngle = $currentAngle + $sliceAngle

        $path = Get-PieSlicePath -CenterX $centerX -CenterY $centerY -Radius $radius -StartAngle $currentAngle -EndAngle $endAngle

        # Create path element
        $pathElement = New-Object System.Windows.Shapes.Path
        $pathElement.Data = [System.Windows.Media.Geometry]::Parse($path)
        $pathElement.Fill = $Colors[$category]
        $Canvas.Children.Add($pathElement) | Out-Null

        $currentAngle = $endAngle
    }
}

function Render-TrendChart {
    <#
    .SYNOPSIS
        Renders a trend line chart

    .DESCRIPTION
        Creates a line chart showing trends over time.

    .EXAMPLE
        Render-TrendChart
    #>
    param()

    if ($null -eq $TrendChartCanvas) { return }

    # Update Trend Chart (placeholder - would need historical data)
    $TrendChartCanvas.Children.Clear()
    $canvasWidth = $TrendChartCanvas.ActualWidth
    $canvasHeight = $TrendChartCanvas.ActualHeight

    if ($canvasWidth -gt 0 -and $canvasHeight -gt 0) {
        $trendData = @(12, 18, 8, 22, 15, 25, 30) # Last 7 days
        $maxTrend = ($trendData | Measure-Object -Maximum).Maximum
        if ($maxTrend -eq 0) { $maxTrend = 1 }
        $pointSpacing = $canvasWidth / ($trendData.Count - 1)

        $points = @()
        for ($i = 0; $i -lt $trendData.Count; $i++) {
            $x = $i * $pointSpacing
            $y = $canvasHeight - (($trendData[$i] / $maxTrend) * $canvasHeight * 0.8) - 10
            $points += [System.Windows.Point]::new($x, $y)
        }

        # Draw line
        $polyline = New-Object System.Windows.Shapes.Polyline
        $polyline.Stroke = "#58A6FF"
        $polyline.StrokeThickness = 2
        $polyline.Points = [System.Windows.PointCollection]::new($points)
        $TrendChartCanvas.Children.Add($polyline) | Out-Null

        # Draw points
        foreach ($pt in $points) {
            $ellipse = New-Object System.Windows.Shapes.Ellipse
            $ellipse.Fill = "#58A6FF"
            $ellipse.Width = 6
            $ellipse.Height = 6
            $ellipse.Margin = [System.Windows.Thickness]::new($pt.X - 3, $pt.Y - 3, 0, 0)
            $TrendChartCanvas.Children.Add($ellipse) | Out-Null
        }

        if ($null -ne $TrendSummaryLabel) {
            $TrendSummaryLabel.Text = "Total events in last 7 days: $(($trendData | Measure-Object -Sum).Sum)"
        }
    }
}

Export-ModuleMember -Function Update-Charts, Get-PieSlicePath, Render-GaugeChart, Render-PieChart, Render-TrendChart
