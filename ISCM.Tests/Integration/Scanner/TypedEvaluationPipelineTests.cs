using ISCM.Application.Evaluators;
using ISCM.Application.Interfaces;
using ISCM.Application.Services;
using ISCM.Application.Services.Agreement;
using ISCM.Application.Evaluators.Typed;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Moq;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Integration.Scanner;

/// <summary>
/// تست‌های یکپارچه برای پایپ‌لاین ارزیابی تایپ‌شده
/// 
/// این تست‌ها تأیید می‌کنند که:
/// 1. جریان کامل: Evidence → Normalize → TypedEvaluation → Agreement → FinalStatus
/// 2. یکپارچگی بین ControlEvaluator و AgreementEngine
/// 3. رفتار end-to-end بدون mock
/// </summary>
public class TypedEvaluationPipelineTests
{
    private readonly ControlEvaluator _controlEvaluator;
    private readonly SubControlAggregationService _aggregationService;
    private readonly DefaultAgreementPolicy _agreementPolicy;

    public TypedEvaluationPipelineTests()
    {
        // Real implementations (no mocks)
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

        _controlEvaluator = new ControlEvaluator(typedEvaluator);
        _agreementPolicy = new DefaultAgreementPolicy();
        _aggregationService = new SubControlAggregationService(_agreementPolicy);
    }

    [Fact]
    public void FullPipeline_IntegerCheck_AllPathsPass_ProducesPassFinding()
    {
        // Arrange - simulate a check with 3 paths all passing
        var subControlResult = new SubControlResult
        {
            SubControlId = "PWD-001.4",
            EvidenceItems = new List<Evidence>()
        };

        // Add 3 evidence items (simulating 3 paths)
        for (int i = 1; i <= 3; i++)
        {
            var evidence = new Evidence
            {
                EvidenceId = $"evidence-{i}",
                PathId = $"path-{i}",
                TypedValue = EvidenceValue.FromInteger(14),
                RawOutput = "14"
            };
            subControlResult.EvidenceItems.Add(evidence);

            // Add PathResult
            var pathResult = new PathResult
            {
                PathId = $"path-{i}",
                Status = CheckStatus.Pass,
                EvidenceId = evidence.EvidenceId
            };
            subControlResult.AddPathResult(pathResult);
        }

        var controlDefinition = new ControlDefinition
        {
            ControlId = "PWD-001",
            Title = "Password Policy",
            Category = CheckCategory.Account,
            Severity = CheckSeverity.High,
            SubControls = new List<SubControlDefinition>
            {
                new SubControlDefinition
                {
                    SubControlId = "PWD-001.4",
                    SettingName = "Minimum password length",
                    ExpectedValue = "14 characters",
                    ExpectedValueType = ExpectedValueType.Integer,
                    Operator = Operator.GreaterOrEqual
                }
            }
        };

        // Act - Step 1: Typed evaluation
        var typedResult = _controlEvaluator.EvaluateSubControlTyped(
            subControlResult,
            "14 characters",
            ExpectedValueType.Integer,
            Operator.GreaterOrEqual);

        // Act - Step 2: Agreement
        _aggregationService.Aggregate(subControlResult);

        // Act - Step 3: Produce Finding
        var finding = _controlEvaluator.EvaluateFromSubControls(
            controlDefinition,
            new List<SubControlResult> { subControlResult },
            "PWD-001");

        // Assert
        typedResult.AggregatedStatus.Should().Be(CheckStatus.Pass);
        subControlResult.HasAgreementDecision.Should().BeTrue();
        subControlResult.AgreementDecision!.SelectedVerdict.Should().Be(CheckStatus.Pass);
        subControlResult.AgreementDecision.AgreementState.Should().Be(AgreementState.FullAgreement);
        finding.Status.Should().Be(CheckStatus.Pass);
    }

    [Fact]
    public void FullPipeline_IntegerCheck_PathDisagreement_ProducesDisagreementFinding()
    {
        // Arrange - simulate 2 pass, 1 fail
        var subControlResult = new SubControlResult
        {
            SubControlId = "PWD-001.4",
            EvidenceItems = new List<Evidence>()
        };

        // Path 1: Pass
        var evidence1 = new Evidence
        {
            EvidenceId = "evidence-1",
            PathId = "path-1",
            TypedValue = EvidenceValue.FromInteger(14),
            RawOutput = "14"
        };
        subControlResult.EvidenceItems.Add(evidence1);
        subControlResult.AddPathResult(new PathResult
        {
            PathId = "path-1",
            Status = CheckStatus.Pass,
            EvidenceId = evidence1.EvidenceId
        });

        // Path 2: Pass
        var evidence2 = new Evidence
        {
            EvidenceId = "evidence-2",
            PathId = "path-2",
            TypedValue = EvidenceValue.FromInteger(14),
            RawOutput = "14"
        };
        subControlResult.EvidenceItems.Add(evidence2);
        subControlResult.AddPathResult(new PathResult
        {
            PathId = "path-2",
            Status = CheckStatus.Pass,
            EvidenceId = evidence2.EvidenceId
        });

        // Path 3: Fail
        var evidence3 = new Evidence
        {
            EvidenceId = "evidence-3",
            PathId = "path-3",
            TypedValue = EvidenceValue.FromInteger(10),
            RawOutput = "10"
        };
        subControlResult.EvidenceItems.Add(evidence3);
        subControlResult.AddPathResult(new PathResult
        {
            PathId = "path-3",
            Status = CheckStatus.Fail,
            EvidenceId = evidence3.EvidenceId
        });

        var controlDefinition = new ControlDefinition
        {
            ControlId = "PWD-001",
            Title = "Password Policy",
            Category = CheckCategory.Account,
            Severity = CheckSeverity.High,
            SubControls = new List<SubControlDefinition>
            {
                new SubControlDefinition
                {
                    SubControlId = "PWD-001.4",
                    SettingName = "Minimum password length",
                    ExpectedValue = "14 characters",
                    ExpectedValueType = ExpectedValueType.Integer,
                    Operator = Operator.GreaterOrEqual
                }
            }
        };

        // Act
        _controlEvaluator.EvaluateSubControlTyped(
            subControlResult,
            "14 characters",
            ExpectedValueType.Integer,
            Operator.GreaterOrEqual);

        _aggregationService.Aggregate(subControlResult);

        var finding = _controlEvaluator.EvaluateFromSubControls(
            controlDefinition,
            new List<SubControlResult> { subControlResult },
            "PWD-001");

        // Assert - CRITICAL: disagreement must produce Disagreement status
        subControlResult.AgreementDecision!.SelectedVerdict.Should().Be(CheckStatus.Disagreement);
        subControlResult.AgreementDecision.AgreementState.Should().Be(AgreementState.Disagreement);
        finding.Status.Should().Be(CheckStatus.Disagreement);
    }

    [Fact]
    public void FullPipeline_BooleanCheck_FailProducesFailFinding()
    {
        // Arrange - single path, expected true, actual false
        var evidence = new Evidence
        {
            EvidenceId = "evidence-1",
            PathId = "path-1",
            TypedValue = EvidenceValue.FromBoolean(false),
            RawOutput = "False"
        };

        var subControlResult = new SubControlResult
        {
            SubControlId = "PWD-001.5",
            EvidenceItems = new List<Evidence> { evidence }
        };

        subControlResult.AddPathResult(new PathResult
        {
            PathId = "path-1",
            Status = CheckStatus.Fail,
            EvidenceId = evidence.EvidenceId
        });

        var controlDefinition = new ControlDefinition
        {
            ControlId = "PWD-001",
            Title = "Password Policy",
            Category = CheckCategory.Account,
            Severity = CheckSeverity.High,
            SubControls = new List<SubControlDefinition>
            {
                new SubControlDefinition
                {
                    SubControlId = "PWD-001.5",
                    SettingName = "Password complexity",
                    ExpectedValue = "Enabled",
                    ExpectedValueType = ExpectedValueType.Boolean,
                    Operator = Operator.Equals
                }
            }
        };

        // Act
        _controlEvaluator.EvaluateSubControlTyped(
            subControlResult,
            "Enabled",
            ExpectedValueType.Boolean,
            Operator.Equals);

        _aggregationService.Aggregate(subControlResult);

        var finding = _controlEvaluator.EvaluateFromSubControls(
            controlDefinition,
            new List<SubControlResult> { subControlResult },
            "PWD-001");

        // Assert
        subControlResult.AgreementDecision!.SelectedVerdict.Should().Be(CheckStatus.Fail);
        finding.Status.Should().Be(CheckStatus.Fail);
    }

    [Fact]
    public void FullPipeline_ErrorPropagation_ErrorOverridesPass()
    {
        // Arrange - 2 pass, 1 error
        var subControlResult = new SubControlResult
        {
            SubControlId = "TEST-001",
            EvidenceItems = new List<Evidence>()
        };

        // Path 1: Pass
        subControlResult.EvidenceItems.Add(new Evidence
        {
            EvidenceId = "evidence-1",
            TypedValue = EvidenceValue.FromInteger(14)
        });
        subControlResult.AddPathResult(new PathResult
        {
            PathId = "path-1",
            Status = CheckStatus.Pass
        });

        // Path 2: Pass
        subControlResult.EvidenceItems.Add(new Evidence
        {
            EvidenceId = "evidence-2",
            TypedValue = EvidenceValue.FromInteger(14)
        });
        subControlResult.AddPathResult(new PathResult
        {
            PathId = "path-2",
            Status = CheckStatus.Pass
        });

        // Path 3: Error
        subControlResult.EvidenceItems.Add(new Evidence
        {
            EvidenceId = "evidence-3",
            TypedValue = null // normalization failed
        });
        subControlResult.AddPathResult(new PathResult
        {
            PathId = "path-3",
            Status = CheckStatus.Error
        });

        var controlDefinition = new ControlDefinition
        {
            ControlId = "TEST-001",
            Title = "Test Control",
            Category = CheckCategory.System,
            Severity = CheckSeverity.Medium,
            SubControls = new List<SubControlDefinition>
            {
                new SubControlDefinition
                {
                    SubControlId = "TEST-001",
                    SettingName = "Test Setting",
                    ExpectedValue = "14",
                    ExpectedValueType = ExpectedValueType.Integer,
                    Operator = Operator.Equals
                }
            }
        };

        // Act
        _controlEvaluator.EvaluateSubControlTyped(
            subControlResult,
            "14",
            ExpectedValueType.Integer,
            Operator.Equals);

        _aggregationService.Aggregate(subControlResult);

        var finding = _controlEvaluator.EvaluateFromSubControls(
            controlDefinition,
            new List<SubControlResult> { subControlResult },
            "TEST-001");

        // Assert - Error must override Pass
        subControlResult.AgreementDecision!.SelectedVerdict.Should().Be(CheckStatus.Error);
        finding.Status.Should().Be(CheckStatus.Error);
    }
}