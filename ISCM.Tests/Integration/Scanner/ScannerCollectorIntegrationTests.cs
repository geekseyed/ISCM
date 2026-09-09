using ISCM.Application.Evaluators;
using ISCM.Application.Interfaces;
using ISCM.Application.Services;
using ISCM.Application.Services.Agreement;
using ISCM.Application.Evaluators.Typed;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using ISCM.Infrastructure.Scanning;
using ISCM.Infrastructure.Scanning.Checks;
using ISCM.Infrastructure.Scanning.Collectors;
using Moq;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Integration.Scanner;

/// <summary>
/// Golden tests for Phase 10.4 → Phase 11.5 — Scanner Integration with Collector-only Checks
/// 
/// این تست‌ها تأیید می‌کنند که Scanner:
/// 1. CollectEvidenceAsync را از چک‌ها فراخوانی می‌کند (تنها متد موجود در Collector-only pattern)
/// 2. Evidence را به SubControlResult تبدیل می‌کند
/// 3. EvaluateSubControlTyped را با متادیتای کاتالوگ فراخوانی می‌کند
/// 4. Agreement را اعمال می‌کند
/// 5. Finding نهایی را تولید می‌کند
/// 
/// Phase 11.5: Removed IMultiPathCheckValidator dependency (legacy removed).
/// </summary>
public class ScannerCollectorIntegrationTests
{
    [Fact]
    public async Task Scanner_CallsCollectEvidenceAsync_AsOnlyCollectionMethod()
    {
        // Arrange
        var mockCheck = new Mock<BaseHardeningCheck>();
        mockCheck.Setup(c => c.CheckId).Returns("TEST-001");
        mockCheck.Setup(c => c.Name).Returns("Test Check");
        mockCheck.Setup(c => c.Category).Returns(CheckCategory.System);
        mockCheck.Setup(c => c.Severity).Returns(CheckSeverity.Medium);

        mockCheck.Setup(c => c.CollectEvidenceAsync())
            .ReturnsAsync(new List<Evidence>
            {
                new Evidence
                {
                    EvidenceId = "TEST-001-SUB-001",
                    SubControlId = "SUB-001",
                    RawOutput = "14",
                    TypedValue = EvidenceValue.FromInteger(14),
                    Evaluation = CheckStatus.NotScanned
                }
            });

        var systemInfoCollector = new WindowsSystemInfoCollector();

        var mockBaselineService = new Mock<IBaselineService>();
        mockBaselineService.Setup(s => s.GetDefaultBaseline())
            .Returns(new BaselineDefinition { BaselineId = "TEST", Name = "Test Baseline", Version = "1.0" });

        var parser = new ExpectedValueParser();
        var typedEvaluator = new TypedEvidenceEvaluator(
            parser,
            new IntegerEvaluator(),
            new LongEvaluator(),
            new BooleanEvaluator(),
            new StringEvaluator(),
            new DurationEvaluator(),
            new SizeEvaluator(),
            new EnumEvaluator(),
            new CollectionEvaluator(),
            new RegistryValueEvaluator(),
            new PolicyValueEvaluator());

        var controlEvaluator = new ControlEvaluator(typedEvaluator);
        var agreementPolicy = new DefaultAgreementPolicy();
        var aggregationService = new SubControlAggregationService(agreementPolicy);

        var mockAcquisitionService = new Mock<IEvidenceAcquisitionService>();
        var mockFreshnessPolicy = new Mock<IScanFreshnessPolicy>();
        mockFreshnessPolicy.Setup(p => p.CanUseCachedEvidence(It.IsAny<ScanContext>(), It.IsAny<Evidence>()))
            .Returns(false);

        var mockFingerprintService = new Mock<IFingerprintValidationService>();
        var mockInvalidationService = new Mock<IScanInvalidationService>();
        var mockNormalizationService = new Mock<INormalizationService>();

        var verificationPathService = new VerificationPathService();

        // Phase 11.5: Scanner constructor now takes 11 parameters (no IMultiPathCheckValidator)
        var scanner = new WindowsHardeningScanner(
            systemInfoCollector,
            new List<IHardeningCheck> { mockCheck.Object },
            controlEvaluator,
            mockBaselineService.Object,
            mockAcquisitionService.Object,
            mockFreshnessPolicy.Object,
            mockFingerprintService.Object,
            mockInvalidationService.Object,
            mockNormalizationService.Object,
            verificationPathService,
            aggregationService
        );

        // Act
        var result = await scanner.RunScanAsync(ScanMode.Full, null);

        // Assert
        result.Should().NotBeNull();
        result.Findings.Should().NotBeEmpty();

        // Verify CollectEvidenceAsync was called (the only collection method now)
        mockCheck.Verify(c => c.CollectEvidenceAsync(), Times.Once);
    }

    [Fact]
    public async Task Scanner_CallsEvaluateSubControlTyped_WithCatalogMetadata()
    {
        // Arrange - استفاده از SMB-001 (ساده‌ترین چک: فقط Boolean + Equals)
        // SMB-001.3 (Allow insecure guest logons): Boolean + Equals + "Disabled"
        // SMB-001.4 (SMB client signing): Boolean + Equals + "Enabled"
        // SMB-001.5 (SMB server signing): Boolean + Equals + "Enabled"
        var mockCheck = new Mock<BaseHardeningCheck>();
        mockCheck.Setup(c => c.CheckId).Returns("SMB-001");
        mockCheck.Setup(c => c.Name).Returns("Disable SMBv1");
        mockCheck.Setup(c => c.Category).Returns(CheckCategory.Network);
        mockCheck.Setup(c => c.Severity).Returns(CheckSeverity.Critical);

        mockCheck.Setup(c => c.CollectEvidenceAsync())
            .ReturnsAsync(new List<Evidence>
            {
                // SMB-001.3: Allow insecure guest logons = Disabled
                new Evidence
                {
                    EvidenceId = "e-3",
                    SubControlId = "SMB-001.3",
                    RawOutput = "Disabled",
                    TypedValue = EvidenceValue.FromBoolean(false),
                    Evaluation = CheckStatus.NotScanned
                },
                // SMB-001.4: SMB client signing = Enabled
                new Evidence
                {
                    EvidenceId = "e-4",
                    SubControlId = "SMB-001.4",
                    RawOutput = "Enabled",
                    TypedValue = EvidenceValue.FromBoolean(true),
                    Evaluation = CheckStatus.NotScanned
                },
                // SMB-001.5: SMB server signing = Enabled
                new Evidence
                {
                    EvidenceId = "e-5",
                    SubControlId = "SMB-001.5",
                    RawOutput = "Enabled",
                    TypedValue = EvidenceValue.FromBoolean(true),
                    Evaluation = CheckStatus.NotScanned
                }
            });

        var systemInfoCollector = new WindowsSystemInfoCollector();

        var mockBaselineService = new Mock<IBaselineService>();
        mockBaselineService.Setup(s => s.GetDefaultBaseline())
            .Returns(new BaselineDefinition { BaselineId = "TEST", Name = "Test Baseline", Version = "1.0" });

        var parser = new ExpectedValueParser();
        var typedEvaluator = new TypedEvidenceEvaluator(
            parser,
            new IntegerEvaluator(),
            new LongEvaluator(),
            new BooleanEvaluator(),
            new StringEvaluator(),
            new DurationEvaluator(),
            new SizeEvaluator(),
            new EnumEvaluator(),
            new CollectionEvaluator(),
            new RegistryValueEvaluator(),
            new PolicyValueEvaluator());

        var controlEvaluator = new ControlEvaluator(typedEvaluator);
        var agreementPolicy = new DefaultAgreementPolicy();
        var aggregationService = new SubControlAggregationService(agreementPolicy);

        var mockAcquisitionService = new Mock<IEvidenceAcquisitionService>();
        var mockFreshnessPolicy = new Mock<IScanFreshnessPolicy>();
        mockFreshnessPolicy.Setup(p => p.CanUseCachedEvidence(It.IsAny<ScanContext>(), It.IsAny<Evidence>()))
            .Returns(false);

        var mockFingerprintService = new Mock<IFingerprintValidationService>();
        var mockInvalidationService = new Mock<IScanInvalidationService>();
        var mockNormalizationService = new Mock<INormalizationService>();

        var verificationPathService = new VerificationPathService();

        // Phase 11.5: Scanner constructor now takes 11 parameters (no IMultiPathCheckValidator)
        var scanner = new WindowsHardeningScanner(
            systemInfoCollector,
            new List<IHardeningCheck> { mockCheck.Object },
            controlEvaluator,
            mockBaselineService.Object,
            mockAcquisitionService.Object,
            mockFreshnessPolicy.Object,
            mockFingerprintService.Object,
            mockInvalidationService.Object,
            mockNormalizationService.Object,
            verificationPathService,
            aggregationService
        );

        // Act
        var result = await scanner.RunScanAsync(ScanMode.Full, null);

        // Assert
        result.Should().NotBeNull();
        result.Findings.Should().HaveCount(1);

        var finding = result.Findings.First();
        finding.CheckId.Should().Be("SMB-001");

        // چاپ خطای دقیق اگر Error بود (برای دیباگ)
        if (finding.Status == CheckStatus.Error)
        {
            Assert.Fail($"Scanner produced Error status. ErrorMessage: {finding.ErrorMessage ?? "(null)"}. Description: {finding.Description}");
        }

        // Scanner باید موفقیت‌آمیز باشد
        finding.Status.Should().NotBe(CheckStatus.Error,
            "Scanner should successfully evaluate SMB-001 SubControls via typed pipeline");

        // همه 3 SubControl باید Pass شوند (چون TypedValue ها دقیقاً با ExpectedValue تطابق دارند)
        finding.Status.Should().Be(CheckStatus.Pass,
            "All 3 SMB-001 SubControls (guest logons disabled, client signing enabled, server signing enabled) " +
            "should pass with correct typed values");
    }
}