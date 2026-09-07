using ISCM.Application.Services.Agreement;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Unit.Agreement;

/// <summary>
/// تست‌های واحد برای DefaultAgreementPolicy
/// 
/// این تست‌ها ماتریس توافق قطعی را تأیید می‌کنند:
/// - PASS/PASS/PASS → PASS
/// - FAIL/FAIL/FAIL → FAIL
/// - PASS/FAIL → DISAGREEMENT (هرگز PASS)
/// - ERROR/* → ERROR
/// - UNKNOWN/* → UNKNOWN
/// </summary>
public class DefaultAgreementPolicyTests
{
    private readonly DefaultAgreementPolicy _policy;

    public DefaultAgreementPolicyTests()
    {
        _policy = new DefaultAgreementPolicy();
    }

    [Fact]
    public void Decide_AllPass_ReturnsPass()
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", CheckStatus.Pass),
            CreatePathResult("path2", CheckStatus.Pass),
            CreatePathResult("path3", CheckStatus.Pass)
        };

        // Act
        var decision = _policy.Decide(paths);

        // Assert
        decision.SelectedVerdict.Should().Be(CheckStatus.Pass);
        decision.AgreementState.Should().Be(AgreementState.FullAgreement);
    }

    [Fact]
    public void Decide_AllFail_ReturnsFail()
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", CheckStatus.Fail),
            CreatePathResult("path2", CheckStatus.Fail),
            CreatePathResult("path3", CheckStatus.Fail)
        };

        // Act
        var decision = _policy.Decide(paths);

        // Assert
        decision.SelectedVerdict.Should().Be(CheckStatus.Fail);
        decision.AgreementState.Should().Be(AgreementState.UnanimousFailure);
    }

    [Fact]
    public void Decide_PassAndFail_ReturnsDisagreement_NeverPass()
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", CheckStatus.Pass),
            CreatePathResult("path2", CheckStatus.Fail)
        };

        // Act
        var decision = _policy.Decide(paths);

        // Assert - CRITICAL: disagreement must NEVER be Pass
        decision.SelectedVerdict.Should().Be(CheckStatus.Disagreement);
        decision.AgreementState.Should().Be(AgreementState.Disagreement);
        decision.SelectedVerdict.Should().NotBe(CheckStatus.Pass);
    }

    [Fact]
    public void Decide_PassPassFail_ReturnsDisagreement()
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", CheckStatus.Pass),
            CreatePathResult("path2", CheckStatus.Pass),
            CreatePathResult("path3", CheckStatus.Fail)
        };

        // Act
        var decision = _policy.Decide(paths);

        // Assert
        decision.SelectedVerdict.Should().Be(CheckStatus.Disagreement);
        decision.AgreementState.Should().Be(AgreementState.Disagreement);
    }

    [Fact]
    public void Decide_AnyError_ReturnsError()
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", CheckStatus.Pass),
            CreatePathResult("path2", CheckStatus.Error),
            CreatePathResult("path3", CheckStatus.Pass)
        };

        // Act
        var decision = _policy.Decide(paths);

        // Assert
        decision.SelectedVerdict.Should().Be(CheckStatus.Error);
        decision.AgreementState.Should().Be(AgreementState.IncompleteVerification);
    }

    [Fact]
    public void Decide_AnyUnknown_ReturnsUnknown()
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", CheckStatus.Pass),
            CreatePathResult("path2", CheckStatus.Unknown),
            CreatePathResult("path3", CheckStatus.Pass)
        };

        // Act
        var decision = _policy.Decide(paths);

        // Assert
        decision.SelectedVerdict.Should().Be(CheckStatus.Unknown);
        decision.AgreementState.Should().Be(AgreementState.IncompleteVerification);
    }

    [Fact]
    public void Decide_EmptyPaths_ReturnsUnknown()
    {
        // Arrange
        var paths = new List<PathResult>();

        // Act
        var decision = _policy.Decide(paths);

        // Assert
        decision.SelectedVerdict.Should().Be(CheckStatus.Unknown);
    }

    [Fact]
    public void Decide_PreservesAllPathResults()
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", CheckStatus.Pass),
            CreatePathResult("path2", CheckStatus.Fail),
            CreatePathResult("path3", CheckStatus.Pass)
        };

        // Act
        var decision = _policy.Decide(paths);

        // Assert - all paths must be preserved
        decision.PathContributions.Should().HaveCount(3);
        decision.PathContributions.Keys.Should().Contain(new[] { "path1", "path2", "path3" });
    }

    [Fact]
    public void Decide_Deterministic_SameInputProducesSameOutput()
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", CheckStatus.Pass),
            CreatePathResult("path2", CheckStatus.Fail),
            CreatePathResult("path3", CheckStatus.Pass)
        };

        // Act - run twice
        var decision1 = _policy.Decide(paths);
        var decision2 = _policy.Decide(paths);

        // Assert
        decision1.SelectedVerdict.Should().Be(decision2.SelectedVerdict);
        decision1.AgreementState.Should().Be(decision2.AgreementState);
        decision1.PassCount.Should().Be(decision2.PassCount);
        decision1.FailCount.Should().Be(decision2.FailCount);
    }

    [Theory]
    [InlineData(CheckStatus.Pass)]
    [InlineData(CheckStatus.Fail)]
    [InlineData(CheckStatus.Error)]
    [InlineData(CheckStatus.Unknown)]
    public void Decide_SinglePath_ReturnsSameStatus(CheckStatus pathStatus)
    {
        // Arrange
        var paths = new List<PathResult>
        {
            CreatePathResult("path1", pathStatus)
        };

        // Act
        var decision = _policy.Decide(paths);

        // Assert
        decision.SelectedVerdict.Should().Be(pathStatus);
        decision.PathContributions.Should().HaveCount(1);
    }

    private static PathResult CreatePathResult(string pathId, CheckStatus status)
    {
        return new PathResult
        {
            PathId = pathId,
            Status = status,
            EvidenceId = $"evidence-{pathId}",
            ExecutedAt = DateTime.UtcNow
        };
    }
}