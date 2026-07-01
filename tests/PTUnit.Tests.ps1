#Requires -Version 7.0
#Requires -Modules Pester

# Unit + contract tests for PhishTriageDeploy. Pure logic runs with no network; Graph-facing
# functions are exercised by mocking Invoke-PTGraphRequest inside the owning module scope.

BeforeAll {
    $src = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
    Import-Module (Join-Path $src 'PTCommon.psm1') -Force
    foreach ($m in 'PTLicense', 'PTIdentity', 'PTPermissions', 'PTReport', 'PTInstructions') {
        Import-Module (Join-Path $src "$m.psm1") -Force
    }
}

Describe 'PTCommon.Get-PTDomainFromUpn' {
    It 'derives the domain from a UPN' {
        Get-PTDomainFromUpn 'admin@contoso.onmicrosoft.com' | Should -Be 'contoso.onmicrosoft.com'
    }
    It 'returns $null for an invalid UPN' {
        Get-PTDomainFromUpn 'not-a-upn' | Should -BeNullOrEmpty
    }
}

Describe 'PTInstructions.ConvertTo-PTLocalPath' {
    It 'passes non-drive paths through unchanged' {
        ConvertTo-PTLocalPath -Path '/home/x/f.md' | Should -Be '/home/x/f.md'
    }
    It 'translates a Windows drive path to a WSL mount on Linux' -Skip:(-not $IsLinux) {
        ConvertTo-PTLocalPath -Path 'C:\SOC\f.md' | Should -Be '/mnt/c/SOC/f.md'
    }
}

Describe 'PTInstructions.Resolve-PTSkillsDocument' {
    It 'Replace uses only the user content' {
        (Resolve-PTSkillsDocument -Mode Replace -UserContent 'MINE').Content | Should -Be 'MINE'
    }
    It 'Append keeps both the default and the user content' {
        $r = Resolve-PTSkillsDocument -Mode Append -UserContent 'ORG-XYZ'
        $r.Content | Should -Match 'ORG-XYZ'
        $r.Source  | Should -Be 'default+user'
    }
    It 'Append/Replace without user content throws' {
        { Resolve-PTSkillsDocument -Mode Replace } | Should -Throw
    }
}

Describe 'PTInstructions.Get-PTDesktopPath' {
    It 'returns a non-empty desktop path' {
        Get-PTDesktopPath | Should -Not -BeNullOrEmpty
    }
}

Describe 'PTInstructions default document paths' {
    It 'resolves the shipped runbook and promptbook defaults to existing files' {
        Test-Path -LiteralPath (Get-PTDefaultSkillsPath)     | Should -BeTrue
        Test-Path -LiteralPath (Get-PTDefaultPromptbookPath) | Should -BeTrue
    }
    It 'resolves a promptbook in Replace mode from its own default path' {
        $r = Resolve-PTSkillsDocument -Mode Replace -UserContent 'PB' -DefaultPath (Get-PTDefaultPromptbookPath)
        $r.Content | Should -Be 'PB'
    }
}

Describe 'PTIdentity.ConvertTo-PTUpnLocalPart' {
    It 'sanitizes a display name to a UPN local part' {
        ConvertTo-PTUpnLocalPart -DisplayName 'Phishing Triage Agent' | Should -Be 'phishing-triage-agent'
    }
}

Describe 'PTPermissions.Get-PTPermissionDrift' {
    It 'reports InSync when declared equals actual (case-insensitive)' {
        $d = Get-PTPermissionDrift -Declared @('A', 'B') -Actual @('b', 'a')
        $d.InSync | Should -BeTrue
    }
    It 'reports Missing and Extra correctly' {
        $d = Get-PTPermissionDrift -Declared @('A', 'B', 'C') -Actual @('A')
        $d.InSync | Should -BeFalse
        $d.Missing | Should -Contain 'B'
        $d.Missing | Should -Contain 'C'
    }
}

Describe 'PTReport.Get-PTExitCodeName' {
    It 'maps known codes' {
        Get-PTExitCodeName -Code 0  | Should -Match 'Success'
        Get-PTExitCodeName -Code 20 | Should -Match 'MdoP2'
    }
}

Describe 'PTCommon.Read-PTInteractiveConfig (mocked prompts)' {
    It 'builds a tenant entry from prompts and defaults' {
        Mock -ModuleName PTCommon Read-Host {
            if ($Prompt -match 'Admin UPN') { 'admin@contoso.onmicrosoft.com' }
            elseif ($Prompt -match 'Add another') { 'n' }
            else { '' }
        }
        $cfg = Read-PTInteractiveConfig
        @($cfg.Tenants).Count | Should -Be 1
        $cfg.Tenants[0].UserPrincipalName | Should -Be 'admin@contoso.onmicrosoft.com'
        $cfg.Tenants[0].SkillsMode | Should -Be 'Default'
    }
}

Describe 'PTLicense.Test-PTMdoPlan2 (mocked Graph)' {
    It 'returns Present when the MDO P2 service plan is enabled' {
        Mock -ModuleName PTLicense Invoke-PTGraphRequest {
            @{ value = @(
                @{ skuPartNumber = 'SPE_E5'; capabilityStatus = 'Enabled';
                   prepaidUnits = @{ enabled = 5 }; consumedUnits = 2;
                   servicePlans = @(
                       @{ servicePlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'; provisioningStatus = 'Success' }
                   ) }
            ) }
        }
        (Test-PTMdoPlan2).Present | Should -BeTrue
    }
    It 'returns not Present when the plan is absent' {
        Mock -ModuleName PTLicense Invoke-PTGraphRequest {
            @{ value = @(
                @{ skuPartNumber = 'FLOW_FREE'; capabilityStatus = 'Enabled';
                   prepaidUnits = @{ enabled = 1 }; consumedUnits = 1;
                   servicePlans = @(@{ servicePlanId = '00000000-0000-0000-0000-000000000000'; provisioningStatus = 'Success' }) }
            ) }
        }
        (Test-PTMdoPlan2).Present | Should -BeFalse
    }
}

Describe 'PTLicense.Get-PTLicenseGate precedence (mocked)' {
    It 'is FailMdo when MDO P2 is absent' {
        Mock -ModuleName PTLicense Invoke-PTGraphRequest { @{ value = @() } }
        (Get-PTLicenseGate).Gate | Should -Be 'FailMdo'
    }
}
