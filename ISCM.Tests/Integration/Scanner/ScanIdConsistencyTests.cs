using FluentAssertions;
using ISCM.Application.Services;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

/// <summary>
/// Phase 13.1: Verifies ScanId consistency between ScanContext and ScanResult.
/// 
/// Background:
///   Previously, ScanContext generated its own ScanId (A) and ScanResult
///   generated a separate ScanId (B) in its constructor. Evidence items
///   received ScanId A from ScanContext, while ScanResult held ScanId B.
///   This broke traceability and would corrupt persistence/diff operations.
/// 
/// Fix:
///   ScanResult now accepts an optional scanId parameter. WindowsHardeningScanner
///   injects scanContext.ScanId into ScanResult, guaranteeing consistency.
/// </summary>
public class ScanIdConsistencyTests
{
    [Fact]
    public void ScanResult_Should_Accept_External_ScanId_From_Context()
    {
        // Arrange
        var expectedScanId = "abc123def456";

        // Act — Constructor 1 (without targetId)
        var result1 = new ScanResult(
            hostname: "TEST-PC",
            ipAddress: "192.168.1.100",
            macAddress: "AA:BB:CC:DD:EE:FF",
            osVersion: "10.0.22621",
            osBuild: "22621",
            mode: ScanMode.Full,
            scanId: expectedScanId);

        // Act — Constructor 2 (with targetId and scannerVersion)
        var result2 = new ScanResult(
            hostname: "TEST-PC",
            ipAddress: "192.168.1.100",
            macAddress: "AA:BB:CC:DD:EE:FF",
            osVersion: "10.0.22621",
            osBuild: "22621",
            mode: ScanMode.Full,
            targetId: "TEST-PC",
            scannerVersion: "2.0.0",
            scanId: expectedScanId);

        // Assert
        result1.ScanId.Should().Be(expectedScanId);
        result2.ScanId.Should().Be(expectedScanId);
    }

    [Fact]
    public void ScanResult_Should_Generate_ScanId_When_Not_Provided_BackwardCompat()
    {
        // Act — Constructor 1 without scanId
        var result1 = new ScanResult(
            hostname: "TEST-PC",
            ipAddress: "192.168.1.100",
            macAddress: "AA:BB:CC:DD:EE:FF",
            osVersion: "10.0.22621",
            osBuild: "22621",
            mode: ScanMode.Full);

        // Act — Constructor 2 without scanId
        var result2 = new ScanResult(
            hostname: "TEST-PC",
            ipAddress: "192.168.1.100",
            macAddress: "AA:BB:CC:DD:EE:FF",
            osVersion: "10.0.22621",
            osBuild: "22621",
            mode: ScanMode.Full,
            targetId: "TEST-PC");

        // Assert
        result1.ScanId.Should().NotBeNullOrEmpty();
        result2.ScanId.Should().NotBeNullOrEmpty();
        result1.ScanId.Should().NotBe(result2.ScanId); // Each generates unique ID
    }

    [Fact]
    public void ScanContext_And_ScanResult_Should_Share_Same_ScanId()
    {
        // Arrange — Simulate what WindowsHardeningScanner does
        var scanContext = new ScanContext("TEST-PC", ScanMode.Full);

        // Act — Scanner injects scanContext.ScanId into ScanResult
        var scanResult = new ScanResult(
            hostname: "TEST-PC",
            ipAddress: "192.168.1.100",
            macAddress: "AA:BB:CC:DD:EE:FF",
            osVersion: "10.0.22621",
            osBuild: "22621",
            mode: ScanMode.Full,
            targetId: "TEST-PC",
            scannerVersion: scanContext.ScannerVersion,
            scanId: scanContext.ScanId);

        // Assert — Critical invariant for Phase 13+ persistence
        scanResult.ScanId.Should().Be(scanContext.ScanId,
            "ScanResult must use the same ScanId as ScanContext for traceability");
    }

    [Fact]
    public void ScanId_Should_Be_32Char_Hex_Without_Dashes()
    {
        // Arrange
        var scanContext = new ScanContext("TEST-PC", ScanMode.Full);

        // Assert — Guid.NewGuid().ToString("N") produces 32 hex chars
        scanContext.ScanId.Should().HaveLength(32);
        scanContext.ScanId.Should().NotContain("-");
        scanContext.ScanId.Should().MatchRegex("^[a-f0-9]{32}$");
    }

    [Fact]
    public void Evidence_Should_Inherit_ScanId_From_Same_Context()
    {
        // Arrange
        var scanContext = new ScanContext("TEST-PC", ScanMode.Full);
        var scanResult = new ScanResult(
            hostname: "TEST-PC",
            ipAddress: "192.168.1.100",
            macAddress: "AA:BB:CC:DD:EE:FF",
            osVersion: "10.0.22621",
            osBuild: "22621",
            mode: ScanMode.Full,
            targetId: "TEST-PC",
            scannerVersion: scanContext.ScannerVersion,
            scanId: scanContext.ScanId);

        var evidence = new Evidence
        {
            ScanId = scanContext.ScanId, // Scanner assigns from context
            SubControlId = "PWD-001.1",
            ParentControlId = "PWD-001",
            SourceType = EvidenceSourceType.Registry,
            SourceName = "RegistryReader"
        };

        // Assert — All three must share the same ScanId
        scanResult.ScanId.Should().Be(scanContext.ScanId);
        evidence.ScanId.Should().Be(scanContext.ScanId);
        evidence.ScanId.Should().Be(scanResult.ScanId);
    }
}