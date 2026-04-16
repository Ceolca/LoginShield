using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace LoginShield;

public class LoginEvent
{
    public string IpAddress { get; set; } = "";
    public string Username { get; set; } = "";
    public bool Success { get; set; }
}

public class SecurityAnalyzer
{
    public List<string> Analyze(List<LoginEvent> events)
    {
        return events.Where(e => !e.Success)
            .GroupBy(e => e.IpAddress)
            .Where(g => g.Count() >= 3)
            .Select(g => $" BRUTE FORCE ALERT: IP {g.Key} - {g.Count()} failed logins (usernames: {string.Join(", ", g.Select(e => e.Username).Distinct())})")
            .ToList();
    }
}

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("LoginShield - Cybersecurity Brute Force Detector");
        Console.WriteLine("================================================");

        var events = new List<LoginEvent>
        {
            new() { IpAddress = "8.8.8.8", Username = "alice", Success = false },
            new() { IpAddress = "8.8.8.8", Username = "bob", Success = false },
            new() { IpAddress = "8.8.8.8", Username = "charlie", Success = false },
            new() { IpAddress = "8.8.8.8", Username = "alice", Success = false },

            new() { IpAddress = "1.1.1.1", Username = "david", Success = true },
            new() { IpAddress = "2.2.2.2", Username = "eve", Success = false }
        };

        Console.WriteLine($"\n Processed {events.Count} login events");
        Console.WriteLine($" Successful: {events.Count(e => e.Success)}");
        Console.WriteLine($" Failed: {events.Count(e => !e.Success)}");

        var analyzer = new SecurityAnalyzer();
        var alerts = analyzer.Analyze(events);

        if (alerts.Any())
        {
            Console.WriteLine("\n SECURITY ALERTS:");
            Console.WriteLine(new string('=', 50));
            foreach (var alert in alerts)
            {
                Console.WriteLine(alert);
            }

            // Save report
            Directory.CreateDirectory("output");
            await File.WriteAllTextAsync("output/report.txt", string.Join("\n", alerts));
            Console.WriteLine("\n Report saved to output/report.txt");
        }
        else
        {
            Console.WriteLine("\n No brute force attacks detected");
        }
    }
}