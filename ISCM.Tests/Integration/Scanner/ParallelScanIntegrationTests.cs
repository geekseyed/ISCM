using ISCM.Application.Evaluators;
using ISCM.Application.Interfaces;
using ISCM.Application.Services;
using ISCM.Application.Services.Agreement;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning;
using ISCM.Infrastructure.Scanning.Checks;
using ISCM.Infrastructure.Scanning.Collectors;
using Moq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class ParallelScanIntegrationTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task RunScanAsync_ExecutesChecksInParallel_CompletesFaster()
    {
        // Arrange
        var config = new ScannerConfiguration { MaxDegreeOfParallelism = Environment.ProcessorCount };
        var configService = new ScannerConfigurationService(config);

        // Create 3 slow checks that each take ~500ms
        var slowChecks = new List<IHardeningCheck>
        {
            CreateSlowCheck("SLOW-001", 500),
            CreateSlowCheck("SLOW-002", 500),
            CreateSlowCheck("SLOW-003", 500)
        };

        var scanner = BuildScanner(slowChecks, configService);

        // Act — Time the parallel execution
        var sw = Stopwatch.StartNew();
        var result = await scanner.RunScanAsync();
        sw.Stop();

        // Assert — Parallel execution should complete in ~500ms, not ~1500ms (serial)
        Assert.True(sw.ElapsedMilliseconds < 1200,
            $"Expected parallel scan < 1200ms but took {sw.ElapsedMilliseconds}ms (serial would be ~1500ms+)");

        Assert.NotNull(result);
        Assert.Equal(3, result.Findings.Count);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task RunScanAsync_RespectsMaxDegreeOfParallelism_LimitsConcurrency()
    {
        // Arrange
        var config = new ScannerConfiguration { MaxDegreeOfParallelism = 1 }; // Force serial
        var configService = new ScannerConfigurationService(config);

        var slowChecks = new List<IHardeningCheck>
        {
            CreateSlowCheck("SLOW-001", 300),
            CreateSlowCheck("SLOW-002", 300)
        };

        var scanner = BuildScanner(slowChecks, configService);

        // Act
        var sw = Stopwatch.StartNew();
        var result = await scanner.RunScanAsync();
        sw.Stop();

        // Assert — With MaxDegreeOfParallelism = 1, should take ~600ms (serial)
        Assert.True(sw.ElapsedMilliseconds >= 500,
            $"Expected serial scan >= 500ms with MaxParallelism=1, but took {sw.ElapsedMilliseconds}ms");
    }

    private IHardeningCheck CreateSlowCheck(string checkId, int delayMs)
    {
        var mock = new Mock<IHardeningCheck>();
        mock.Setup(c => c.CheckId).Returns(checkId);
        mock.Setup(c => c.Name).Returns($"Slow Check {checkId}");
        mock.Setup(c => c.Category).Returns(CheckCategory.System);
        mock.Setup(c => c.Severity).Returns(CheckSeverity.Medium);

        // Also implement IEvidenceCollector
        var collectorMock = mock.As<IEvidenceCollector>();
        collectorMock.Setup(c => c.CollectorId).Returns(checkId);
        collectorMock.Setup(c => c.CollectEvidenceAsync())
            .Returns(async () =>
            {
                await Task.Delay(delayMs);
                return new List<Evidence>
                {
                    new Evidence
                    {
                        SubControlId = $"{checkId}.1",
                        RawOutput = "slow",
                        TypedValue = ISCM.Domain.ValueObjects.EvidenceValue.FromString("slow"),
                        Evaluation = CheckStatus.NotScanned
                    }
                };
            });

        return mock.Object;
    }

    private WindowsHardeningScanner BuildScanner(IEnumerable<IHardeningCheck> checks, IScannerConfigurationService configService)
    {
        var sysInfoCollector = new WindowsSystemInfoCollector();
        var controlEvaluator = new ControlEvaluator();
        var baselineService = new Mock<IBaselineService>();
        baselineService.Setup(s => s.GetDefaultBaseline()).Returns(new BaselineDefinition
        {
            BaselineId = "test",
            Name = "Test",
            Version = "1.0"
        });

        var acquisitionService = new Mock<IEvidenceAcquisitionService>();
        var freshnessPolicy = new Mock<IScanFreshnessPolicy>();
        freshnessPolicy.Setup(p => p.CanUseCachedEvidence(It.IsAny<ScanContext>(), It.IsAny<Evidence>())).Returns(false);

        var fingerprintService = new Mock<IFingerprintValidationService>();
        var invalidationService = new Mock<IScanInvalidationService>();
        var normalizationService = new Mock<INormalizationService>();
        var verificationPathService = new VerificationPathService();
        var agreementPolicy = new Mock<IAgreementPolicy>();
        var aggregationService = new SubControlAggregationService(agreementPolicy.Object);

        return new WindowsHardeningScanner(
            sysInfoCollector,
            checks,
            controlEvaluator,
            baselineService.Object,
            acquisitionService.Object,
            freshnessPolicy.Object,
            fingerprintService.Object,
            invalidationService.Object,
            normalizationService.Object,
            verificationPathService,
            aggregationService,
            configService
        );
    }
}