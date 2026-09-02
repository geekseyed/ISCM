using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public static class ExtendedControlDefinitions
{
    public static void PopulateExtendedControls()
    {
        var ext01 = ControlCatalog.GetAll().FirstOrDefault(c => c.ControlId == "EXT-01");
        if (ext01 != null && (ext01.SubControls == null || !ext01.SubControls.Any()))
        {
            ext01.SubControls = new List<SubControlDefinition>
            {
                new()
                {
                    SubControlId = "EXT-01.1",
                    SettingName = "Windows Defender Real-Time Protection",
                    Description = "Real-time protection must be enabled",
                    ExpectedValue = "Enabled",
                    EvidenceSources = new List < string > { "PowerShell", "Registry" },
                    Category = CheckCategory.System,
                    Severity = CheckSeverity.High,
                    IsRequired = true,
                    ParentControlId = "EXT-01",
                    ExpectedValueType = ExpectedValueType.Boolean,
                    Operator = Operator.Equals,
                    RequiredPathCount = 1,
                    RemediationIds = new List<string> { "REM-DEF-001" }
                },
                new()
                {
                    SubControlId = "EXT-01.2",
                    SettingName = "Windows Defender AntiSpyware",
                    Description = "AntiSpyware must be enabled",
                    ExpectedValue = "Enabled",
                    EvidenceSources = new List < string > { "PowerShell", "Registry" },
                    Category = CheckCategory.System,
                    Severity = CheckSeverity.High,
                    IsRequired = true,
                    ParentControlId = "EXT-01",
                    ExpectedValueType = ExpectedValueType.Boolean,
                    Operator = Operator.Equals,
                    RequiredPathCount = 1,
                    RemediationIds = new List<string> { "REM-DEF-002" }
                }
            };
        }

        var ext02 = ControlCatalog.GetAll().FirstOrDefault(c => c.ControlId == "EXT-02");
        if (ext02 != null && (ext02.SubControls == null || !ext02.SubControls.Any()))
        {
            ext02.SubControls = new List<SubControlDefinition>
            {
                new()
                {
                    SubControlId = "EXT-02.1",
                    SettingName = "USB Storage Service Disabled",
                    Description = "USBSTOR service must be disabled",
                    ExpectedValue = "Disabled",
                    EvidenceSources = new List<string> { "PowerShell", "Registry" },
                    Category = CheckCategory.System,
                    Severity = CheckSeverity.Medium,
                    IsRequired = true,
                    ParentControlId = "EXT-02",
                    ExpectedValueType = ExpectedValueType.Boolean,
                    Operator = Operator.Equals,
                    RequiredPathCount = 1,
                    RemediationIds = new List<string> { "REM-USB-001" }
                },
                new()
                {
                    SubControlId = "EXT-02.2",
                    SettingName = "USB Write Protection",
                    Description = "USB devices should be read-only or blocked",
                    ExpectedValue = "1",
                    EvidenceSources = new List < string > { "PowerShell", "Registry" },
                    Category = CheckCategory.System,
                    Severity = CheckSeverity.Medium,
                    IsRequired = false,
                    ParentControlId = "EXT-02",
                    ExpectedValueType = ExpectedValueType.Integer,
                    Operator = Operator.Equals,
                    RequiredPathCount = 1,
                    RemediationIds = new List<string> { "REM-USB-002" }
                }
            };
        }

        var ext03 = ControlCatalog.GetAll().FirstOrDefault(c => c.ControlId == "EXT-03");
        if (ext03 != null && (ext03.SubControls == null || !ext03.SubControls.Any()))
        {
            ext03.SubControls = new List<SubControlDefinition>
            {
                new()
                {
                    SubControlId = "EXT-03.1",
                    SettingName = "AutoLogon Disabled",
                    Description = "AutoAdminLogon must be disabled",
                    ExpectedValue = "0",
                    EvidenceSources = new List < string > { "PowerShell", "Registry" },
                    Category = CheckCategory.Account,
                    Severity = CheckSeverity.High,
                    IsRequired = true,
                    ParentControlId = "EXT-03",
                    ExpectedValueType = ExpectedValueType.Integer,
                    Operator = Operator.Equals,
                    RequiredPathCount = 1,
                    RemediationIds = new List<string> { "REM-ALG-001" }
                },
                new()
                {
                    SubControlId = "EXT-03.2",
                    SettingName = "Default Password Cleared",
                    Description = "DefaultPassword registry value must not exist or be empty",
                    ExpectedValue = "Empty",
                    EvidenceSources = new List < string > { "PowerShell", "Registry" },
                    Category = CheckCategory.Account,
                    Severity = CheckSeverity.High,
                    IsRequired = true,
                    ParentControlId = "EXT-03",
                    ExpectedValueType = ExpectedValueType.String,
                    Operator = Operator.Equals,
                    RequiredPathCount = 1,
                    RemediationIds = new List<string> { "REM-ALG-002" }
                }
            };
        }
    }
}