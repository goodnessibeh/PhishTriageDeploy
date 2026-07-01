@{
    # This is interactive admin tooling: coloured host output is intentional, so
    # PSAvoidUsingWriteHost is excluded (parity with MDOMigrate). Everything else uses the
    # default PSScriptAnalyzer rule set. Target: 0 Warnings and 0 Errors.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
}
