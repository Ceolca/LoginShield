using Xunit;
using LoginShield;
using System.IO;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;

namespace LoginShield.Tests;

public class SecurityAnalyzerTests
{
    private readonly string _testJsonPath = "logs.json";

    [Fact]
    public void Analyze_RealLogsJson_DetectsBruteForceAttack()
    {
        if (!File.Exists(_testJsonPath))
            Assert.Fail($"Test data file '{_testJsonPath}' not found in test project!");

        var json = File.ReadAllText(_testJsonPath);
        var events = JsonConvert.DeserializeObject<List<LoginEvent>>(json)!;

        // Act
        var analyzer = new SecurityAnalyzer();
        var alerts = analyzer.Analyze(events);

        // Assert
        Assert.NotEmpty(alerts);
        Assert.Single(alerts);
        Assert.Contains("8.8.8.8", alerts[0]);
        Assert.Contains("4 failed", alerts[0]);
    }

    [Fact]
    public void Analyze_RealLogsJson_StatisticsCorrect()
    {
        var json = File.ReadAllText(_testJsonPath);
        var events = JsonConvert.DeserializeObject<List<LoginEvent>>(json)!;

        Assert.Equal(6, events.Count);
        Assert.Equal(1, events.Count(e => e.Success));
        Assert.Equal(5, events.Count(e => !e.Success));
        Assert.Contains(events, e => e.IpAddress == "8.8.8.8");
    }

    [Fact]
    public void Analyze_RealLogsJson_AllFieldsPopulated()
    {
        var json = File.ReadAllText(_testJsonPath);
        var events = JsonConvert.DeserializeObject<List<LoginEvent>>(json)!;

        foreach (var evt in events)
        {
            Assert.NotEmpty(evt.IpAddress);
            Assert.NotEmpty(evt.Username);
        }
    }
}