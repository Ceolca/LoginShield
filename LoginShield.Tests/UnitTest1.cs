using Xunit;
using LoginShield;
using System.Collections.Generic;
using System.Linq;

namespace LoginShield.Tests;

public class SecurityAnalyzerTests
{
    private List<LoginEvent> GetSampleEvents()
    {
        return new List<LoginEvent>
        {
            new() { IpAddress = "8.8.8.8", Username = "alice", Success = false },
            new() { IpAddress = "8.8.8.8", Username = "bob", Success = false },
            new() { IpAddress = "8.8.8.8", Username = "charlie", Success = false },
            new() { IpAddress = "8.8.8.8", Username = "alice", Success = false },

            new() { IpAddress = "1.1.1.1", Username = "david", Success = true },
            new() { IpAddress = "2.2.2.2", Username = "eve", Success = false }
        };
    }

    [Fact]
    public void Analyze_DetectsBruteForceAttack()
    {
        var events = GetSampleEvents();
        var analyzer = new SecurityAnalyzer();

        var alerts = analyzer.Analyze(events);

        Assert.NotEmpty(alerts);
        Assert.Single(alerts);
        Assert.Contains("8.8.8.8", alerts[0]);
        Assert.Contains("4 failed", alerts[0]);
    }

    [Fact]
    public void Analyze_StatisticsCorrect()
    {
        var events = GetSampleEvents();

        Assert.Equal(6, events.Count);
        Assert.Equal(1, events.Count(e => e.Success));
        Assert.Equal(5, events.Count(e => !e.Success));
        Assert.Contains(events, e => e.IpAddress == "8.8.8.8");
    }

    [Fact]
    public void Analyze_AllFieldsPopulated()
    {
        var events = GetSampleEvents();

        foreach (var evt in events)
        {
            Assert.NotEmpty(evt.IpAddress);
            Assert.NotEmpty(evt.Username);
        }
    }

    [Fact]
    public void Analyze_NoBruteForce_ReturnsEmpty()
    {
        var events = new List<LoginEvent>
        {
            new() { IpAddress = "1.1.1.1", Username = "user1", Success = false },
            new() { IpAddress = "2.2.2.2", Username = "user2", Success = false }
        };

        var analyzer = new SecurityAnalyzer();
        var alerts = analyzer.Analyze(events);

        Assert.Empty(alerts);
    }
}